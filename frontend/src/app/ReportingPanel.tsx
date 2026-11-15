"use client";

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

interface SourceOption {
  id: string;
  label: string;
}

interface ReviewDecision {
  id: string;
  reviewer_id: string;
  decision: string;
  notes: string | null;
  created_at: string;
}

interface Finding {
  id: string;
  created_by: string;
  title: string;
  narrative: string;
  source_record_ids: string[];
  source_snapshot: { sources: Array<Record<string, unknown>> };
  review_status: string;
  review_history: ReviewDecision[];
  created_at: string;
}

interface Report {
  id: string;
  created_by: string;
  title: string;
  body: string;
  finding_ids: string[];
  source_snapshot: {
    findings: Array<{
      id: string;
      title: string;
      source_record_ids: string[];
    }>;
  };
  review_status: string;
  review_history: ReviewDecision[];
  created_at: string;
}

interface AuditEvent {
  id: string;
  actor_id: string;
  action: string;
  target_type: string;
  target_id: string;
  metadata: Record<string, unknown>;
  occurred_at: string;
}

interface SearchHit {
  source_type: string;
  source_record_id: string;
  title: string;
  excerpt: string;
  occurred_at: string;
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

async function requestJson<T>(
  path: string,
  csrfToken: string,
  init?: RequestInit,
): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.method && init.method !== "GET") {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    ...init,
    headers,
  });
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    const detail =
      typeof body === "object" &&
      body !== null &&
      "detail" in body &&
      typeof body.detail === "string"
        ? body.detail
        : `Request failed (${response.status})`;
    throw new Error(
      detail,
    );
  }
  return (await response.json()) as T;
}

function statusStyle(value: string): string {
  if (value === "approved") return "border-emerald-800 bg-emerald-950 text-emerald-200";
  if (value === "rejected") return "border-rose-800 bg-rose-950 text-rose-200";
  return "border-amber-800 bg-amber-950 text-amber-200";
}

export default function ReportingPanel({
  caseId,
  caseStatus,
  csrfToken,
  currentUserId,
  canWrite,
  canReview,
  sourceOptions,
}: {
  caseId: string;
  caseStatus: string;
  csrfToken: string;
  currentUserId: string;
  canWrite: boolean;
  canReview: boolean;
  sourceOptions: SourceOption[];
}) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busy, setBusy] = useState(false);
  const [findingTitle, setFindingTitle] = useState("");
  const [findingNarrative, setFindingNarrative] = useState("");
  const [selectedSources, setSelectedSources] = useState<string[]>([]);
  const [reportTitle, setReportTitle] = useState("");
  const [selectedFindings, setSelectedFindings] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [searchHits, setSearchHits] = useState<SearchHit[]>([]);
  const [searchError, setSearchError] = useState("");
  const [searched, setSearched] = useState(false);

  const reload = useCallback(async (signal?: AbortSignal) => {
    const [findingResult, reportResult, auditResult] = await Promise.allSettled([
      requestJson<Finding[]>(`/cases/${caseId}/findings`, csrfToken, { signal }),
      requestJson<Report[]>(`/cases/${caseId}/reports`, csrfToken, { signal }),
      requestJson<AuditEvent[]>(`/cases/${caseId}/audit-log`, csrfToken, { signal }),
    ]);
    if (signal?.aborted) return;
    setLoadError("");
    const failures: string[] = [];
    if (findingResult.status === "fulfilled") setFindings(findingResult.value);
    else failures.push("findings");
    if (reportResult.status === "fulfilled") setReports(reportResult.value);
    else failures.push("reports");
    if (auditResult.status === "fulfilled") setAuditEvents(auditResult.value);
    else failures.push("audit history");
    if (failures.length) setLoadError(`Could not load ${failures.join(", ")}.`);
    setLoading(false);
  }, [caseId, csrfToken]);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      await reload(controller.signal);
    }
    void load();
    return () => controller.abort();
  }, [caseId, csrfToken, reload]);

  async function createFinding(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setActionError("");
    try {
      const finding = await requestJson<Finding>(`/cases/${caseId}/findings`, csrfToken, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: findingTitle,
          narrative: findingNarrative,
          source_record_ids: selectedSources,
        }),
      });
      setFindings((current) => [finding, ...current]);
      setFindingTitle("");
      setFindingNarrative("");
      setSelectedSources([]);
      await reload();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Finding could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  async function reviewFinding(finding: Finding, decision: "approved" | "rejected") {
    setBusy(true);
    setActionError("");
    try {
      await requestJson(
        `/cases/${caseId}/findings/${finding.id}/reviews`,
        csrfToken,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ decision }),
        },
      );
      await reload();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Review decision failed.");
    } finally {
      setBusy(false);
    }
  }

  async function createReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setActionError("");
    try {
      await requestJson(`/cases/${caseId}/reports`, csrfToken, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: reportTitle,
          finding_ids: selectedFindings,
        }),
      });
      setReportTitle("");
      setSelectedFindings([]);
      await reload();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Report could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  async function reviewReport(report: Report, decision: "approved" | "rejected") {
    setBusy(true);
    setActionError("");
    try {
      await requestJson(
        `/cases/${caseId}/reports/${report.id}/reviews`,
        csrfToken,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ decision }),
        },
      );
      await reload();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Review decision failed.");
    } finally {
      setBusy(false);
    }
  }

  async function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSearchError("");
    try {
      const result = await requestJson<SearchHit[]>(
        `/cases/${caseId}/search?q=${encodeURIComponent(query)}`,
        csrfToken,
      );
      setSearchHits(result);
      setSearched(true);
    } catch (error) {
      setSearchError(error instanceof Error ? error.message : "Search failed.");
    }
  }

  return (
    <div className="space-y-6">
      {loadError && (
        <p className="rounded-lg border border-rose-900 bg-rose-950/50 p-3 text-sm text-rose-200" role="alert">
          {loadError}
        </p>
      )}
      {actionError && (
        <p className="rounded-lg border border-rose-900 bg-rose-950/50 p-3 text-sm text-rose-200" role="alert">
          {actionError}
        </p>
      )}

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6">
        <h2 className="text-lg font-semibold text-white">Search this case</h2>
        <form className="mt-4 flex flex-wrap gap-2" onSubmit={(event) => void search(event)}>
          <label className="sr-only" htmlFor="case-search">Search case records</label>
          <input
            id="case-search"
            className="min-w-60 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            minLength={2}
            maxLength={200}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search evidence, timeline, findings, reports…"
            value={query}
          />
          <button
            className="rounded-lg border border-slate-600 px-4 py-2 text-sm font-medium text-slate-200 hover:border-cyan-400"
            type="submit"
          >
            Search
          </button>
        </form>
        {searchError && <p className="mt-3 text-sm text-rose-300">{searchError}</p>}
        {searchHits.length > 0 && (
          <ul className="mt-4 divide-y divide-slate-800">
            {searchHits.map((hit) => (
              <li className="py-3" key={`${hit.source_type}-${hit.source_record_id}`}>
                  <a
                    className="font-medium text-cyan-200 hover:underline"
                    href={
                      hit.source_type === "finding"
                        ? `#finding-${hit.source_record_id}`
                        : hit.source_type === "report"
                          ? `#report-${hit.source_record_id}`
                          : hit.source_type === "evidence"
                            ? "#timeline-heading"
                            : `#source-${hit.source_record_id}`
                    }
                  >
                  {hit.title}
                </a>
                <p className="mt-1 text-xs text-slate-500">
                  {hit.source_type} · {formatTime(hit.occurred_at)}
                </p>
                {hit.excerpt && <p className="mt-1 text-sm text-slate-400">{hit.excerpt}</p>}
              </li>
            ))}
          </ul>
        )}
        {searched && !searchHits.length && !searchError && (
          <p className="mt-3 text-sm text-slate-500">No matching records.</p>
        )}
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6">
          <p className="text-xs font-semibold tracking-wide text-cyan-300">EXAMINER RECORD</p>
          <h2 className="mt-1 text-lg font-semibold text-white">Findings</h2>
          {canWrite && caseStatus === "open" && (
            <form className="mt-4 space-y-3 border-b border-slate-800 pb-5" onSubmit={(event) => void createFinding(event)}>
              <label className="block text-xs text-slate-400" htmlFor="finding-title">Title</label>
              <input
                id="finding-title"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                maxLength={200}
                onChange={(event) => setFindingTitle(event.target.value)}
                required
                value={findingTitle}
              />
              <label className="block text-xs text-slate-400" htmlFor="finding-narrative">Finding and analysis</label>
              <textarea
                id="finding-narrative"
                className="min-h-24 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                maxLength={10_000}
                onChange={(event) => setFindingNarrative(event.target.value)}
                required
                value={findingNarrative}
              />
              <fieldset>
                <legend className="mb-2 text-xs text-slate-400">Cite case records</legend>
                <div className="flex flex-wrap gap-2">
                  {sourceOptions.map((source) => (
                    <label className="flex items-center gap-2 rounded border border-slate-700 px-2 py-1 text-xs text-slate-300" key={source.id}>
                      <input
                        checked={selectedSources.includes(source.id)}
                        onChange={(event) =>
                          setSelectedSources((current) =>
                            event.target.checked
                              ? [...current, source.id]
                              : current.filter((id) => id !== source.id),
                          )
                        }
                        type="checkbox"
                      />
                      {source.label}
                    </label>
                  ))}
                </div>
              </fieldset>
              <button
                className="rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
                disabled={busy || selectedSources.length === 0}
                type="submit"
              >
                Save immutable finding
              </button>
            </form>
          )}
          {loading && <p className="mt-4 text-sm text-slate-400">Loading findings…</p>}
          {!loading && findings.length === 0 && (
            <p className="mt-4 text-sm text-slate-400">No findings recorded.</p>
          )}
          <div className="mt-4 space-y-3">
            {findings.map((finding) => (
              <article className="rounded-xl border border-slate-800 bg-slate-950/70 p-4" id={`finding-${finding.id}`} key={finding.id}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="font-medium text-white">{finding.title}</h3>
                  <span className={`rounded-full border px-2 py-1 text-[11px] font-semibold uppercase ${statusStyle(finding.review_status)}`}>
                    {finding.review_status}
                  </span>
                </div>
                <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-300">{finding.narrative}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {finding.source_record_ids.map((sourceId) => (
                    <a className="rounded border border-cyan-900 px-2 py-1 font-mono text-[11px] text-cyan-200" href={`#source-${sourceId}`} key={sourceId}>
                      Source {sourceId.slice(0, 8)}
                    </a>
                  ))}
                </div>
                <p className="mt-3 text-xs text-slate-500">Created {formatTime(finding.created_at)}</p>
                {finding.review_history.map((review) => (
                  <p className="mt-2 text-xs text-slate-400" key={review.id}>
                    {review.decision} by {review.reviewer_id} · {formatTime(review.created_at)}
                    {review.notes ? ` · ${review.notes}` : ""}
                  </p>
                ))}
                {canReview && finding.created_by !== currentUserId && (
                  <div className="mt-3 flex gap-2">
                    <button className="rounded border border-emerald-800 px-3 py-1.5 text-xs text-emerald-200 disabled:opacity-50" disabled={busy} onClick={() => void reviewFinding(finding, "approved")} type="button">Approve</button>
                    <button className="rounded border border-rose-800 px-3 py-1.5 text-xs text-rose-200 disabled:opacity-50" disabled={busy} onClick={() => void reviewFinding(finding, "rejected")} type="button">Reject</button>
                  </div>
                )}
              </article>
            ))}
          </div>
          {caseStatus !== "open" && (
            <p className="mt-4 text-xs text-slate-500">Closed cases are read-only.</p>
          )}
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6">
          <p className="text-xs font-semibold tracking-wide text-violet-300">PROVENANCE-BACKED OUTPUT</p>
          <h2 className="mt-1 text-lg font-semibold text-white">Reports</h2>
          {canWrite && caseStatus === "open" && findings.length > 0 && (
            <form className="mt-4 space-y-3 border-b border-slate-800 pb-5" onSubmit={(event) => void createReport(event)}>
              <label className="block text-xs text-slate-400" htmlFor="report-title">Report title</label>
              <input
                id="report-title"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                maxLength={200}
                onChange={(event) => setReportTitle(event.target.value)}
                required
                value={reportTitle}
              />
              <fieldset>
                <legend className="mb-2 text-xs text-slate-400">Include findings</legend>
                <div className="space-y-2">
                  {findings.map((finding) => (
                    <label className="flex items-start gap-2 text-sm text-slate-300" key={finding.id}>
                      <input
                        checked={selectedFindings.includes(finding.id)}
                        onChange={(event) =>
                          setSelectedFindings((current) =>
                            event.target.checked
                              ? [...current, finding.id]
                              : current.filter((id) => id !== finding.id),
                          )
                        }
                        type="checkbox"
                      />
                      <span>{finding.title} <span className="text-xs text-slate-500">({finding.review_status})</span></span>
                    </label>
                  ))}
                </div>
              </fieldset>
              <button className="rounded-lg bg-violet-300 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50" disabled={busy || selectedFindings.length === 0} type="submit">
                Create immutable report draft
              </button>
            </form>
          )}
          {loading && <p className="mt-4 text-sm text-slate-400">Loading reports…</p>}
          {!loading && reports.length === 0 && <p className="mt-4 text-sm text-slate-400">No reports created.</p>}
          <div className="mt-4 space-y-3">
            {reports.map((report) => (
              <article className="rounded-xl border border-slate-800 bg-slate-950/70 p-4" id={`report-${report.id}`} key={report.id}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="font-medium text-white">{report.title}</h3>
                  <span className={`rounded-full border px-2 py-1 text-[11px] font-semibold uppercase ${statusStyle(report.review_status)}`}>
                    {report.review_status}
                  </span>
                </div>
                <pre className="mt-3 whitespace-pre-wrap break-words font-sans text-sm leading-6 text-slate-300">{report.body}</pre>
                <p className="mt-3 text-xs text-slate-500">
                  {report.finding_ids.length} findings · Created {formatTime(report.created_at)}
                </p>
                <ul className="mt-3 space-y-2 border-t border-slate-800 pt-3">
                  {report.source_snapshot.findings.map((finding) => (
                    <li className="text-xs text-slate-400" key={finding.id}>
                      {finding.title}
                      <div className="mt-1 flex flex-wrap gap-2">
                        {finding.source_record_ids.map((sourceId) => (
                          <a
                            className="rounded border border-cyan-900 px-2 py-1 font-mono text-[10px] text-cyan-200"
                            href={`#source-${sourceId}`}
                            key={sourceId}
                          >
                            Source {sourceId.slice(0, 8)}
                          </a>
                        ))}
                      </div>
                    </li>
                  ))}
                </ul>
                {report.review_history.map((review) => (
                  <p className="mt-2 text-xs text-slate-400" key={review.id}>
                    {review.decision} by {review.reviewer_id} · {formatTime(review.created_at)}
                    {review.notes ? ` · ${review.notes}` : ""}
                  </p>
                ))}
                {canReview && report.created_by !== currentUserId && (
                  <div className="mt-3 flex gap-2">
                    <button className="rounded border border-emerald-800 px-3 py-1.5 text-xs text-emerald-200 disabled:opacity-50" disabled={busy} onClick={() => void reviewReport(report, "approved")} type="button">Approve</button>
                    <button className="rounded border border-rose-800 px-3 py-1.5 text-xs text-rose-200 disabled:opacity-50" disabled={busy} onClick={() => void reviewReport(report, "rejected")} type="button">Reject</button>
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      </div>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6">
        <p className="text-xs font-semibold tracking-wide text-slate-400">APPEND-ONLY RECORD</p>
        <h2 className="mt-1 text-lg font-semibold text-white">Audit history</h2>
        {loading && <p className="mt-4 text-sm text-slate-400">Loading audit history…</p>}
        {!loading && auditEvents.length === 0 && (
          <p className="mt-4 text-sm text-slate-400">No audited case actions recorded.</p>
        )}
        {auditEvents.length > 0 && (
          <ol className="mt-4 divide-y divide-slate-800">
            {auditEvents.map((event) => (
              <li className="flex flex-wrap items-center justify-between gap-3 py-3" key={event.id}>
                <div>
                  <p className="text-sm font-medium text-slate-200">{event.action.replaceAll("_", " ")}</p>
                  <p className="mt-1 font-mono text-[11px] text-slate-500">
                    {event.target_type} · {event.target_id} · actor {event.actor_id}
                  </p>
                </div>
                <time className="text-xs text-slate-500" dateTime={event.occurred_at}>
                  {formatTime(event.occurred_at)}
                </time>
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}
