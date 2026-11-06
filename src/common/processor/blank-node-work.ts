/**
 * URDNA2015 search-cost guard — port of blankNodeWork in go-credential-sdk
 * credential/common/processor/canonicalize_idmap.go (go #165).
 */

export class BlankNodeWorkError extends Error {
  constructor() {
    super('too many interchangeable blank nodes');
    this.name = 'BlankNodeWorkError';
  }
}

/**
 * Admits every document in this SDK's tests, and refuses anything shaped like
 * the known attacks (a clique of 4 scores 46656). A cap on the number of blank
 * nodes cannot do this: a clique of 9 takes URDNA2015 half a minute.
 */
export const maxBlankNodeWork = 20000;

type Term = { termType: string; value: string; datatype?: { value: string }; language?: string };
type Quad = { subject: Term; predicate: Term; object: Term; graph: Term };

const isBlank = (t: Term): boolean => t.termType === 'BlankNode';

// Hash First Degree Quads rule: the node under test reads as _:a, every other as _:z.
function masked(t: Term, id: string): string {
  if (!isBlank(t)) return `${t.termType}|${t.value}|${t.datatype?.value ?? ''}|${t.language ?? ''}`;
  return t.value === id ? '_:a' : '_:z';
}

/**
 * Scores the search URDNA2015 will do. A blank node whose quads, with blank
 * nodes masked, match no other node's is labelled at once and costs nothing.
 * The rest are interchangeable: a group of them joined by shared quads scores
 * the product of the orderings of their related lists, times its size, times
 * its edges to blank nodes. Quads with no other blank node are left out.
 * Returns early once the score exceeds the cap.
 */
export function blankNodeWork(dataset: Quad[]): number {
  const lines = new Map<string, string[]>();
  const related = new Map<string, { how: string; id: string }[]>();
  const push = <T>(m: Map<string, T[]>, k: string, v: T) => {
    const l = m.get(k);
    if (l) l.push(v);
    else m.set(k, [v]);
  };
  for (const q of dataset) {
    const nodes = [q.subject, q.object, q.graph];
    for (const n of nodes) {
      if (!isBlank(n)) continue;
      const id = n.value;
      push(lines, id, `${masked(nodes[0], id)} ${q.predicate.value} ${masked(nodes[1], id)} ${masked(nodes[2], id)}`);
      nodes.forEach((other, i) => {
        if (isBlank(other) && other.value !== id) {
          // Hash Related Blank Node leaves the predicate out for a graph name.
          push(related, id, { how: i < 2 ? `${i}${q.predicate.value}` : 'g', id: other.value });
        }
      });
    }
  }

  // Signatures are interned because a list key below copies one per relation.
  const signatures = new Map<string, number>();
  const interned = new Map<string, number>();
  const sharing = new Map<number, number>();
  for (const [id, l] of lines) {
    const sig = [...l].sort().join('\n');
    let n = interned.get(sig);
    if (n === undefined) {
      n = interned.size;
      interned.set(sig, n);
    }
    signatures.set(id, n);
    sharing.set(n, (sharing.get(n) ?? 0) + 1);
  }
  const interchangeable = (id: string) => (sharing.get(signatures.get(id)!) ?? 0) > 1;

  let work = 0;
  const seen = new Set<string>();
  for (const start of lines.keys()) {
    if (seen.has(start) || !interchangeable(start)) continue;
    seen.add(start);
    const group = [start];
    let orderings = 1;
    let edges = 0;
    for (let i = 0; i < group.length; i++) {
      const rel = related.get(group[i]) ?? [];
      edges += rel.length;
      // Lists can repeat a node; the permutator then yields the distinct
      // orderings: the running multinomial of each list.
      const counts = new Map<string, number>();
      for (const r of rel) {
        const list = `${r.how}\0${signatures.get(r.id)}`;
        const c1 = (counts.get(list) ?? 0) + 1;
        const c2 = (counts.get(`${list}\0${r.id}`) ?? 0) + 1;
        counts.set(list, c1);
        counts.set(`${list}\0${r.id}`, c2);
        orderings = Math.floor((orderings * c1) / c2);
        if (orderings > maxBlankNodeWork) return orderings;
        if (!seen.has(r.id) && interchangeable(r.id)) {
          seen.add(r.id);
          group.push(r.id);
        }
      }
    }
    const search = orderings * group.length;
    if (search > 1 && (work += search * edges) > maxBlankNodeWork) return work;
  }
  return work;
}
