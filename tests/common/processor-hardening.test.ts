/**
 * Port of go-credential-sdk #165 tests: document_loader_test.go,
 * canonicalize_blanknode_test.go, context_terms_test.go.
 */
import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import {
  BlankNodeWorkError,
  ContextAddressError,
  ContextBudget,
  ContextLoadError,
  ContextOverflowError,
  ContextRequestsError,
  ContextSchemeError,
  ContextTermTooLongError,
  ContextTimeoutError,
  ContextTooLargeError,
  TooManyContextTermsError,
  blankNodeWork,
  bundledContextUrls,
  cacheSize,
  canonicalizeDocument,
  canonicalizeNQuadsWithIdMap,
  canonicalizeRDF,
  canonicalizeWithIdMap,
  causedBy,
  contextLimits,
  createHttpClient,
  expandJSONLD,
  isPublicAddr,
  maxBlankNodeWork,
  maxCachedContexts,
  maxContextBytes,
  maxContextBytesPerOperation,
  maxContextRequests,
  maxContextTermBytes,
  maxContextTerms,
  maxInlineContextTerms,
  setDocumentLoaderHttpClient,
  toRDFNQuads,
} from '../../src/common/processor/processor';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const jsonld = require('jsonld');

type Doc = Record<string, unknown>;
type Entry = (d: Doc) => Promise<unknown>;

// ---------------------------------------------------------------- helpers

const servers: http.Server[] = [];
const sockets = new Set<Socket>();
const releases: (() => void)[] = [];

async function contextServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ url: string; host: string; server: http.Server }> {
  const server = http.createServer(handler);
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  servers.push(server);
  const port = (server.address() as AddressInfo).port;
  return { url: `http://127.0.0.1:${port}`, host: `127.0.0.1:${port}`, server };
}

/** Reach the loopback test servers: the default client refuses them. */
const useTestClient = () => setDocumentLoaderHttpClient(createHttpClient({ allowNonPublic: true }));

afterEach(async () => {
  releases.splice(0).forEach((r) => r());
  sockets.forEach((s) => s.destroy());
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
  setDocumentLoaderHttpClient(null);
  contextLimits.fetchTimeoutMs = 10_000;
});

function writeContext(res: http.ServerResponse, term: string): void {
  res.setHeader('Content-Type', 'application/ld+json');
  res.end(`{"@context":{"${term}":"https://example.org/${term}"}}`);
}

const docUsing = (contextUrl: string, term: string): Doc => ({
  '@context': contextUrl,
  '@id': 'https://example.org/subject',
  [term]: 'value',
});

/** The loader as jsonld sees it, for one operation. */
const newLoader = () =>
  new ContextBudget({ local: () => undefined, bundledSize: () => undefined });

const isNetFree = (e: unknown) => e instanceof Error;

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error('expected a rejection');
}

// ---------------------------------------------------------- blank-node work

const linkContext = {
  knows: { '@id': 'https://example.org/knows', '@type': '@id' },
  name: 'https://example.org/name',
};

function graphOf(nodes: number, targets: (i: number) => number[]): Doc {
  const graph = Array.from({ length: nodes }, (_, i) => ({
    '@id': `_:n${i}`,
    knows: targets(i).map((j) => ({ '@id': `_:n${j}` })),
  }));
  return { '@context': linkContext, '@graph': graph };
}

// The attack: every node links to every other. 9 nodes is 1.4 KB.
const blankClique = (n: number) =>
  graphOf(n, (i) => Array.from({ length: n }, (_, j) => j).filter((j) => j !== i));
const blankCycle = (n: number) => graphOf(n, (i) => [(i + 1) % n]);

const canonicalizers: Record<string, Entry> = {
  canonicalizeDocument: (d) => canonicalizeDocument(d),
  canonicalizeRDF: (d) => canonicalizeRDF(d),
  canonicalizeWithIdMap: (d) => canonicalizeWithIdMap(d),
  canonicalizeNQuadsWithIdMap: async (d) => canonicalizeNQuadsWithIdMap(await toRDFNQuads(d)),
};

const repeated = (value: string, n: number) => Array.from({ length: n }, () => value);
const toDataset = (d: Doc) => jsonld.toRDF(d, {});

describe('blank-node work cap', () => {
  const expensive: Record<string, Doc> = {
    'clique of 9': blankClique(9),
    'clique of 40': blankClique(40),
    'cycle of 1000': blankCycle(1000),
  };
  for (const [name, doc] of Object.entries(expensive)) {
    for (const [fn, canonicalize] of Object.entries(canonicalizers)) {
      it(`refuses ${name} / ${fn}`, async () => {
        const start = Date.now();
        const err = await rejection(canonicalize(doc));
        expect(err).toBeInstanceOf(BlankNodeWorkError);
        expect(Date.now() - start).toBeLessThan(2000);
      });
    }
  }

  const proof = (graph: string, id: string) => ({
    '@id': graph,
    '@graph': [{ '@id': id, name: 'same proof' }],
  });
  const shapes: Record<string, Doc> = {
    '300 anonymous objects': {
      '@context': linkContext,
      knows: Array.from({ length: 300 }, (_, i) => ({ name: `course ${i}` })),
    },
    '300 identical objects': {
      '@context': linkContext,
      knows: Array.from({ length: 300 }, () => ({ name: 'same' })),
    },
    'interchangeable proofs': {
      '@context': linkContext,
      '@graph': [proof('_:g1', '_:p1'), proof('_:g2', '_:p2')],
    },
    'list of one value': {
      '@context': { values: { '@id': 'https://example.org/values', '@container': '@list' } },
      values: repeated('x', 60),
    },
  };
  for (const [name, doc] of Object.entries(shapes)) {
    for (const [fn, canonicalize] of Object.entries(canonicalizers)) {
      it(`accepts ${name} / ${fn}`, async () => {
        await expect(canonicalize(doc)).resolves.toBeDefined();
      });
    }
  }

  it('keeps a clique just inside the score cheap', async () => {
    const dataset = await toDataset(blankClique(3));
    const work = blankNodeWork(dataset);
    expect(work).toBeGreaterThan(0);
    expect(work).toBeLessThanOrEqual(maxBlankNodeWork);
    await expect(canonicalizeWithIdMap(blankClique(3))).resolves.toBeDefined();
  });

  it('refuses a few nodes with many edges', async () => {
    const nodes = Array.from({ length: 100 }, (_, i) => {
      const node: Doc = { '@id': `_:b${i}` };
      for (let p = 0; p < 96; p++) node[`p${p}`] = { '@id': `_:b${(i + p + 1) % 100}` };
      return node;
    });
    const doc = { '@context': { '@vocab': 'https://example.org/' }, '@graph': nodes };
    const start = Date.now();
    expect(await rejection(canonicalizeRDF(doc))).toBeInstanceOf(BlankNodeWorkError);
    expect(Date.now() - start).toBeLessThan(3000);
  });

  it('puts the limit at a list of 102 equal values', async () => {
    const list = (n: number): Doc => ({
      '@context': { values: { '@id': 'https://example.org/values', '@container': '@list' } },
      values: repeated('x', n),
    });
    expect(blankNodeWork(await toDataset(list(102)))).toBe(maxBlankNodeWork);
    await expect(canonicalizeRDF(list(102))).resolves.toBeDefined();
    expect(await rejection(canonicalizeRDF(list(103)))).toBeInstanceOf(BlankNodeWorkError);
  });

  it('scores 0 for groups with nothing to order', async () => {
    const children = Array.from({ length: 2000 }, (_, i) => ({
      name: 'same',
      knows: { name: String(i) },
    }));
    const dataset = await toDataset({
      '@context': linkContext,
      knows: { knows: children },
    });
    expect(blankNodeWork(dataset)).toBe(0);
  });

  it('scores a big literal-heavy dataset without being the cost itself', async () => {
    const children = Array.from({ length: 5000 }, () => ({ name: 'same' }));
    const dataset = await toDataset({ '@context': linkContext, knows: { knows: children } });
    const start = Date.now();
    expect(blankNodeWork(dataset)).toBe(0);
    expect(Date.now() - start).toBeLessThan(2000);
  });

  it('canonicalizeDocument keeps legacy semantics (matches jsonld.canonize, safe off)', async () => {
    const doc: Doc = {
      '@context': { term: 'https://example.org/term' },
      '@id': 'https://example.org/subject',
      term: 'value',
      undefinedTerm: 'silently dropped',
      proof: { '@type': 'https://example.org/Proof', term: 'p' },
    };
    const got = Buffer.from(await canonicalizeDocument(doc)).toString('utf8');
    const want = await jsonld.canonize(doc, {
      algorithm: 'URDNA2015',
      format: 'application/n-quads',
      safe: false,
    });
    expect(got).toBe(want);
    expect(got).not.toContain('undefinedTerm');
  });
});

// -------------------------------------------------------------- term bounds

const inlineTerms = (n: number) =>
  Object.fromEntries(Array.from({ length: n }, (_, i) => [`t${i}`, `https://example.org/vocab#t${i}`]));

const docWithContext = (ctx: unknown, term: string): Doc => ({
  '@context': ctx,
  '@id': 'https://example.org/subject',
  [term]: 'value',
});

const termEntries: Record<string, Entry> = {
  canonicalizeDocument: canonicalizers.canonicalizeDocument,
  canonicalizeRDF: canonicalizers.canonicalizeRDF,
  canonicalizeWithIdMap: canonicalizers.canonicalizeWithIdMap,
  expandJSONLD: (d) => expandJSONLD(d),
  toRDFNQuads: (d) => toRDFNQuads(d),
};

describe('context term bounds', () => {
  for (const [fn, entry] of Object.entries(termEntries)) {
    it(`inline limit / ${fn}`, async () => {
      await expect(entry(docWithContext(inlineTerms(maxInlineContextTerms), 't0'))).resolves.toBeDefined();
      const err = await rejection(entry(docWithContext(inlineTerms(maxInlineContextTerms + 1), 't0')));
      expect(err).toBeInstanceOf(TooManyContextTermsError);
    });
  }

  it('inline count reaches every context', async () => {
    const over = inlineTerms(maxInlineContextTerms + 1);
    const docs: Record<string, Doc> = {
      node: {
        '@context': { knows: 'https://example.org/knows' },
        knows: [{ '@context': over, t0: 'value' }],
      },
      array: { '@context': [inlineTerms(1), over], t0: 'value' },
      nested: { '@context': [{ '@context': over }], t0: 'value' },
      scoped: {
        '@context': { t0: { '@id': 'https://example.org/t0', '@context': over } },
        t0: 'value',
      },
    };
    for (const doc of Object.values(docs)) {
      expect(await rejection(expandJSONLD(doc))).toBeInstanceOf(TooManyContextTermsError);
    }
  });

  it('remote limit', async () => {
    const bodies: Record<string, string> = {};
    const ctx = (n: number) =>
      JSON.stringify({ '@context': inlineTerms(n) });
    bodies['/at'] = ctx(maxContextTerms);
    bodies['/past'] = ctx(maxContextTerms + 1);
    const srv = await contextServer((req, res) => res.end(bodies[req.url!]));
    useTestClient();
    await expect(canonicalizeDocument(docUsing(srv.url + '/at', 't0'))).resolves.toBeDefined();
    const err = await rejection(canonicalizeDocument(docUsing(srv.url + '/past', 't0')));
    expect(causedBy(err, TooManyContextTermsError)).toBe(true);
  });

  it('a context named many times counts once', async () => {
    const body = JSON.stringify({ '@context': inlineTerms(maxContextTerms / 2) });
    const srv = await contextServer((_req, res) => res.end(body));
    useTestClient();
    const doc: Doc = {
      '@context': [srv.url, { knows: 'https://example.org/knows' }],
      '@id': 'https://example.org/subject',
      t0: 'value',
      knows: { '@context': [srv.url, { knows: 'https://example.org/knows' }], t0: 'value' },
    };
    await expect(canonicalizeRDF(doc)).resolves.toBeDefined();
  });

  describe('length limit', () => {
    const long = (n: number) => {
      const prefix = 'https://example.org/';
      return prefix + 'x'.repeat(n - prefix.length);
    };
    const shapes: Record<string, (n: number) => Doc> = {
      'term IRI': (n) => docWithContext({ term: long(n) }, 'term'),
      'term @id': (n) => docWithContext({ term: { '@id': long(n) } }, 'term'),
      'term name': (n) => {
        const name = 'x'.repeat(n);
        return docWithContext({ '@vocab': 'https://example.org/', [name]: 'https://example.org/term' }, name);
      },
      '@vocab': (n) => docWithContext({ '@vocab': long(n) }, 'term'),
      '@base': (n) => ({
        '@context': { '@base': long(n), term: 'https://example.org/term' },
        '@id': 'https://example.org/subject',
        term: 'value',
      }),
    };
    for (const [name, doc] of Object.entries(shapes)) {
      it(name, async () => {
        await expect(canonicalizeRDF(doc(maxContextTermBytes))).resolves.toBeDefined();
        expect(await rejection(canonicalizeRDF(doc(maxContextTermBytes + 1)))).toBeInstanceOf(
          ContextTermTooLongError,
        );
      });
    }
  });

  const prefixChain = (links: number, value: number) => {
    const ctx: Record<string, string> = { t0: 'https://example.org/' };
    for (let i = 1; i <= links; i++) {
      const name = `t${i - 1}`;
      ctx[`t${i}`] = `${name}:${'x'.repeat(value - name.length - 2)}/`;
    }
    ctx.last = `t${links}:last`;
    return ctx;
  };

  it('chain limit', async () => {
    const value = 100;
    const links = Math.floor(maxContextTermBytes / value);
    const spare = maxContextTermBytes % value;
    const at = prefixChain(links, value);
    at.t0 = `urn:${'x'.repeat(spare - 6)}:/`;
    await expect(canonicalizeRDF(docWithContext(at, 'last'))).resolves.toBeDefined();
    const past = prefixChain(links, value);
    past.t0 = `urn:${'x'.repeat(spare - 5)}:/`;
    expect(await rejection(canonicalizeRDF(docWithContext(past, 'last')))).toBeInstanceOf(
      ContextTermTooLongError,
    );
  });

  it('chain shapes', async () => {
    const suffix = 'x'.repeat(1000) + '/';
    const vocabChain: unknown[] = [{ '@vocab': 'https://example.org/' }];
    for (let i = 0; i < 4; i++) vocabChain.push({ '@vocab': suffix });
    const aliases: Record<string, string> = { t0: 'https://example.org/' };
    for (let i = 1; i < 4; i++) {
      aliases[`a${i - 1}`] = `t${i - 1}`;
      aliases[`t${i}`] = `a${i - 1}:${suffix}`;
    }
    aliases.last = 't3:last';
    const twoNames = [
      { a: 'https://example.org/', b: `a:${suffix}` },
      { a: `b:${suffix}` },
      { b: `a:${suffix}` },
      { a: `b:${suffix}`, last: 'a:last' },
    ];
    const compactNames: unknown[] = [{ t0: 'https://example.org/' }];
    for (let i = 1; i < 4; i++) {
      compactNames.push({ '@vocab': `t${i - 1}:${suffix}`, [`t${i}`]: {} });
    }
    for (const ctx of [vocabChain, aliases, twoNames, compactNames]) {
      expect(await rejection(expandJSONLD(docWithContext(ctx, 'last')))).toBeInstanceOf(
        ContextTermTooLongError,
      );
    }
  });

  it('a chain crossing inline and remote is one chain', async () => {
    const suffix = 'x'.repeat(1000) + '/';
    const srv = await contextServer((_req, res) =>
      res.end(JSON.stringify({ '@context': { t1: `t0:${suffix}`, t3: `t2:${suffix}` } })),
    );
    useTestClient();
    const ctx = [
      { t0: 'https://example.org/' },
      srv.url,
      { t2: `t1:${suffix}`, t4: `t3:${suffix}`, last: 't4:last' },
    ];
    const err = await rejection(expandJSONLD(docWithContext(ctx, 'last')));
    expect(causedBy(err, ContextTermTooLongError)).toBe(true);
  });

  it('accepts real shapes', async () => {
    const ctx: Record<string, unknown> = {
      schema: 'https://schema.org/',
      xsd: 'http://www.w3.org/2001/XMLSchema#',
      ex: 'urn:example:',
      id: '@id',
      type: '@type',
    };
    for (let i = 0; i < maxInlineContextTerms - 5 - 2; i++) {
      ctx[`t${i}`] = { '@id': `schema:t${i}`, '@type': 'xsd:string' };
    }
    ctx.alias = 't0';
    ctx.self = 'self';
    ctx['@vocab'] = 'https://example.org/vocab#';
    await expect(canonicalizeRDF(docWithContext(ctx, 'alias'))).resolves.toBeDefined();
  });
});

// ------------------------------------------------------------ remote loading

describe('remote context loader', () => {
  it('serves concurrent custom contexts', async () => {
    const srv = await contextServer((_req, res) => writeContext(res, 'term'));
    useTestClient();
    await Promise.all(
      Array.from({ length: 16 }, async (_, g) => {
        for (let i = 0; i < 20; i++) {
          const url = i % 2 === 0 ? `${srv.url}/${g}-${i}` : `${srv.url}/${i}`;
          const got = Buffer.from(await canonicalizeDocument(docUsing(url, 'term'))).toString();
          expect(got).toContain('https://example.org/term');
        }
      }),
    );
  });

  it('a slow fetch blocks nothing else', async () => {
    let started!: () => void;
    const startedP = new Promise<void>((r) => (started = r));
    const srv = await contextServer((req, res) => {
      if (req.url === '/slow') {
        started();
        releases.push(() => writeContext(res, 'term'));
        return;
      }
      writeContext(res, 'term');
    });
    useTestClient();
    await newLoader().loadDocument(srv.url + '/cached');
    const slow = newLoader().loadDocument(srv.url + '/slow').catch(() => undefined);
    await startedP;
    await Promise.all([
      newLoader().loadDocument(srv.url + '/cached'),
      newLoader().loadDocument(srv.url + '/other'),
    ]);
    releases.splice(0).forEach((r) => r());
    await slow;
  });

  it('caches a copy per caller', async () => {
    let hits = 0;
    const srv = await contextServer((_req, res) => {
      hits++;
      writeContext(res, 'term');
    });
    useTestClient();
    for (let i = 0; i < 2; i++) {
      const doc = await newLoader().loadDocument(srv.url);
      (doc.document as Doc)['@context'] = 'mutated';
    }
    const last = await newLoader().loadDocument(srv.url);
    expect((last.document as Doc)['@context']).not.toBe('mutated');
    expect(hits).toBe(1);
  });

  it('bounds the cache', async () => {
    const srv = await contextServer((_req, res) => writeContext(res, 'term'));
    useTestClient();
    expect(maxCachedContexts * maxContextBytes).toBeLessThanOrEqual(64 << 20);
    for (let i = 0; i < maxCachedContexts; i++) await newLoader().loadDocument(`${srv.url}/${i}`);
    expect(cacheSize()).toBe(maxCachedContexts);
    await newLoader().loadDocument(`${srv.url}/${maxCachedContexts}`);
    expect(cacheSize()).toBe(maxCachedContexts);
  });

  it('caches the fetched tree exactly', async () => {
    const body =
      '{"@context":{"<a>":"https://example.org/é\\u2028&"},"n":[1,1.0,1e2,-0.5],"x":[' +
      '{},'.repeat(1000) +
      '{}]}';
    const srv = await contextServer((_req, res) => res.end(body));
    useTestClient();
    const fetched = await newLoader().loadDocument(srv.url);
    const cached = await newLoader().loadDocument(srv.url);
    expect(cached).toEqual(fetched);
  });

  it('default client refuses loopback, with one indistinguishable error text', async () => {
    let hits = 0;
    const srv = await contextServer((_req, res) => {
      hits++;
      writeContext(res, 'term');
    });
    const port = srv.url.split(':')[2];
    const closed = await contextServer((_req, res) => res.end());
    const closedUrl = closed.url;
    await new Promise((r) => closed.server.close(r));
    servers.splice(servers.indexOf(closed.server), 1);

    const messages: string[] = [];
    for (const url of [srv.url, `http://localhost:${port}`, closedUrl]) {
      const err = (await rejection(canonicalizeDocument(docUsing(url, 'term')))) as Error;
      messages.push(err.message.split(url).join('URL'));
    }
    expect(hits).toBe(0);
    expect(messages[0]).toBe(messages[2]);
    for (const leak of ['refused', 'dial', 'status', 'not public', 'ECONN']) {
      expect(messages[0]).not.toContain(leak);
    }
  });

  it('isPublicAddr', () => {
    const table: Record<string, boolean> = {
      '8.8.8.8': true,
      '1.1.1.1': true,
      '2606:4700:4700::1111': true,
      '127.0.0.1': false,
      '0.0.0.0': false,
      '10.0.0.1': false,
      '100.64.0.1': false,
      '100.100.100.200': false,
      '169.254.169.254': false,
      '172.16.0.1': false,
      '192.168.1.1': false,
      '198.18.0.1': false,
      '224.0.0.1': false,
      '255.255.255.255': false,
      '::': false,
      '::1': false,
      'fe80::1': false,
      'fe80::1%en0': false,
      'fc00::1': false,
      'fd00:ec2::254': false,
      'ff02::1': false,
      '::ffff:127.0.0.1': false,
      '::ffff:169.254.169.254': false,
      '::169.254.169.254': false,
      '64:ff9b::a9fe:a9fe': false,
      '2002:a9fe:a9fe::': false,
      '': false,
      'not an ip': false,
    };
    for (const [addr, want] of Object.entries(table)) expect([addr, isPublicAddr(addr)]).toEqual([addr, want]);
  });

  it('refuses other schemes', async () => {
    for (const url of ['/etc/hostname', 'file:///etc/hostname', 'ftp://example.org/context']) {
      expect(await rejection(newLoader().loadDocument(url))).toBeInstanceOf(ContextLoadError);
    }
    const srv = await contextServer((_req, res) => {
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Link', '<ftp:context.json>; rel="alternate"; type="application/ld+json"');
      res.end();
    });
    useTestClient();
    expect(causedBy(await rejection(newLoader().loadDocument(srv.url)), ContextSchemeError)).toBe(true);
  });

  it('refuses an oversized response', async () => {
    const srv = await contextServer((req, res) => {
      const pad = req.url === '/over' ? maxContextBytes + 100 : maxContextBytes - 100;
      res.end(`{"pad":"${'x'.repeat(pad)}"}`);
    });
    useTestClient();
    await expect(newLoader().loadDocument(srv.url + '/under')).resolves.toBeDefined();
    const err = await rejection(newLoader().loadDocument(srv.url + '/over'));
    expect(causedBy(err, ContextTooLargeError)).toBe(true);
  });

  it('times out a stalled body', async () => {
    const srv = await contextServer((_req, res) => {
      res.writeHead(200);
      res.write('{"@context":');
      releases.push(() => res.end());
    });
    useTestClient();
    contextLimits.fetchTimeoutMs = 100;
    const start = Date.now();
    const err = await rejection(newLoader().loadDocument(srv.url));
    expect(causedBy(err, ContextTimeoutError)).toBe(true);
    expect(Date.now() - start).toBeLessThan(5000);
  });

  it('bounds an alternate chain', async () => {
    let hits = 0;
    const srv = await contextServer((_req, res) => {
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Link', `</${++hits}>; rel="alternate"; type="application/ld+json"`);
      res.end();
    });
    useTestClient();
    const err = await rejection(newLoader().loadDocument(srv.url));
    expect(causedBy(err, ContextRequestsError)).toBe(true);
    expect(hits).toBe(maxContextRequests);
  });

  it('a context including itself errors', async () => {
    const srv = await contextServer((req, res) => res.end(`{"@context":"http://${req.headers.host}/"}`));
    useTestClient();
    const doc = docUsing(srv.url + '/', 'term');
    for (const entry of [canonicalizeDocument, canonicalizeRDF, toRDFNQuads] as Entry[]) {
      expect(isNetFree(await rejection(entry(doc)))).toBe(true);
    }
  });

  it('budget stops at the deadline, bundled contexts need none', async () => {
    const b = new ContextBudget({
      local: (url) => (url.includes('w3.org') ? { contextUrl: null, document: {}, documentUrl: url } : undefined),
      bundledSize: (url) => (url.includes('w3.org') ? 100 : undefined),
    });
    b.deadline = Date.now() - 1000;
    expect(await rejection(b.loadDocument('https://example.org/context'))).toBeInstanceOf(ContextOverflowError);
    await expect(b.loadDocument('https://www.w3.org/ns/credentials/v2')).resolves.toBeDefined();
    expect(bundledContextUrls()).toContain('https://www.w3.org/ns/credentials/v2');
  });

  it('budget bounds the loads of one operation', async () => {
    const srv = await contextServer((_req, res) => writeContext(res, 'term'));
    useTestClient();
    const b = newLoader();
    b.loads = 1024;
    expect(await rejection(b.loadDocument(srv.url))).toBeInstanceOf(ContextOverflowError);
  });

  it('budget bounds the bytes of one operation', async () => {
    const srv = await contextServer((_req, res) => writeContext(res, 'term'));
    useTestClient();
    const size = Buffer.byteLength('{"@context":{"term":"https://example.org/term"}}');
    const at = newLoader();
    at.bytes = maxContextBytesPerOperation - size;
    await expect(at.loadDocument(srv.url)).resolves.toBeDefined();
    const past = newLoader();
    past.bytes = maxContextBytesPerOperation - size + 1;
    expect(await rejection(past.loadDocument(srv.url))).toBeInstanceOf(ContextOverflowError);

    const bundled = new ContextBudget({
      local: (url) => ({ contextUrl: null, document: {}, documentUrl: url }),
      bundledSize: () => 1000,
    });
    bundled.bytes = maxContextBytesPerOperation - 1000;
    await expect(bundled.loadDocument('x')).resolves.toBeDefined();
    expect(await rejection(bundled.loadDocument('x'))).toBeInstanceOf(ContextOverflowError);
  });

  it('loads through the client hook only, redirects and alternates included', async () => {
    let hits = 0;
    const srv = await contextServer((req, res) => {
      if (req.url === '/context') {
        hits++;
        return writeContext(res, 'term');
      }
      if (req.url === '/redirect') {
        res.writeHead(302, { Location: '/page' });
        return res.end();
      }
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Link', '</context>; rel="alternate"; type="application/ld+json"');
      res.end();
    });
    useTestClient();
    for (const path of ['/context', '/redirect']) {
      const got = Buffer.from(await canonicalizeRDF(docUsing(srv.url + path, 'term'))).toString();
      expect(got).toContain('<https://example.org/term> "value"');
    }
    setDocumentLoaderHttpClient(null);
    hits = 0;
    await rejection(canonicalizeRDF(docUsing(srv.url + '/context', 'term')));
    expect(hits).toBe(0);
  });

  it('keeps the cause on the chain only', async () => {
    const srv = await contextServer((req, res) => {
      if (req.url === '/big') return res.end(`{"pad":"${'x'.repeat(maxContextBytes)}"}`);
      if (req.url === '/notjson') return res.end('<html>');
      res.writeHead(500);
      res.end();
    });
    useTestClient();
    const big = (await rejection(newLoader().loadDocument(srv.url + '/big'))) as Error;
    expect(big).toBeInstanceOf(ContextLoadError);
    expect(causedBy(big, ContextTooLargeError)).toBe(true);
    for (const path of ['/notjson', '/500']) {
      const err = (await rejection(newLoader().loadDocument(srv.url + path))) as Error;
      expect(err.message).toBe(big.message);
    }
  });

  describe('errors are reachable through the library wrapping', () => {
    it('address', async () => {
      const srv = await contextServer((_req, res) => writeContext(res, 'term'));
      const err = await rejection(canonicalizeDocument(docUsing(srv.url, 'term')));
      expect(causedBy(err, ContextAddressError)).toBe(true);
      expect(causedBy(err, ContextLoadError)).toBe(true);
    });
    it('scheme', async () => {
      const err = await rejection(canonicalizeRDF(docUsing('ftp://example.org/context', 'term')));
      expect(causedBy(err, ContextSchemeError)).toBe(true);
      expect(causedBy(err, ContextLoadError)).toBe(true);
    });
    it('alternate scheme', async () => {
      const srv = await contextServer((_req, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Link', '<ftp:context.json>; rel="alternate"; type="application/ld+json"');
        res.end();
      });
      useTestClient();
      expect(causedBy(await rejection(canonicalizeRDF(docUsing(srv.url, 'term'))), ContextSchemeError)).toBe(true);
    });
    it('unparsable alternate', async () => {
      const srv = await contextServer((_req, res) => {
        res.setHeader('Link', '<http://[bad>; rel="alternate"; type="application/ld+json"');
        writeContext(res, 'term');
      });
      useTestClient();
      expect(causedBy(await rejection(toRDFNQuads(docUsing(srv.url, 'term'))), ContextSchemeError)).toBe(true);
    });
    it('requests', async () => {
      let hits = 0;
      const srv = await contextServer((_req, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Link', `</${++hits}>; rel="alternate"; type="application/ld+json"`);
        res.end();
      });
      useTestClient();
      expect(causedBy(await rejection(canonicalizeRDF(docUsing(srv.url, 'term'))), ContextRequestsError)).toBe(true);
    });
    it('deadline', async () => {
      const srv = await contextServer((_req, res) => releases.push(() => res.end()));
      useTestClient();
      contextLimits.fetchTimeoutMs = 50;
      expect(causedBy(await rejection(canonicalizeRDF(docUsing(srv.url, 'term'))), ContextTimeoutError)).toBe(true);
    });
  });
});

describe('library failures become clean errors', () => {
  it('stack overflow on hostile nesting', async () => {
    let deep: Doc = { x: 'leaf' };
    for (let i = 0; i < 200000; i++) deep = { a: deep };
    const doc = { '@context': { a: 'https://example.org/a' }, ...deep };
    const err = (await rejection(expandJSONLD(doc))) as Error;
    expect(err.message).toMatch(/malformed JSON-LD input/);
  });
});
