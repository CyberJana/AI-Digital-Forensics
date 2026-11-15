const navigation = [
  "Overview",
  "Cases",
  "Evidence",
  "Timeline",
  "Reports",
];

export default function Home() {
  return (
    <main className="min-h-screen md:flex">
      <aside className="border-b border-slate-800 bg-slate-950 p-6 md:min-h-screen md:w-64 md:border-b-0 md:border-r">
        <p className="text-sm font-semibold tracking-wide text-cyan-300">
          AI DIGITAL FORENSICS
        </p>
        <nav aria-label="Main navigation" className="mt-8">
          <ul className="flex flex-wrap gap-2 md:flex-col">
            {navigation.map((item, index) => (
              <li key={item}>
                {index === 0 ? (
                  <a
                    aria-current="page"
                    className="block rounded-lg bg-slate-800 px-3 py-2 text-sm text-white"
                    href="/"
                  >
                    {item}
                  </a>
                ) : (
                  <span
                    aria-disabled="true"
                    className="block rounded-lg px-3 py-2 text-sm text-slate-500"
                  >
                    {item} <span className="text-xs">(planned)</span>
                  </span>
                )}
              </li>
            ))}
          </ul>
        </nav>
      </aside>
      <section className="flex-1 p-6 md:p-10">
        <header>
          <p className="text-sm text-cyan-300">INVESTIGATION WORKSPACE</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">
            Digital Forensics Investigation Portal
          </h1>
          <p className="mt-3 max-w-2xl text-slate-400">
            A secure workspace for managing investigations and preserving
            evidence provenance.
          </p>
        </header>
        <section
          aria-labelledby="foundation-status"
          className="mt-10 max-w-3xl rounded-xl border border-slate-800 bg-slate-900/60 p-6"
        >
          <h2 id="foundation-status" className="text-lg font-medium text-white">
            Foundation milestone
          </h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            The dashboard shell is ready. Case management, evidence processing,
            authentication, and reporting are not implemented yet.
          </p>
        </section>
      </section>
    </main>
  );
}
