"use client";

import { useEffect, useMemo, useState } from "react";
import ReportingPanel from "./ReportingPanel";
import EvidenceStoragePanel from "./EvidenceStoragePanel";

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

interface Organization {
  id: string;
  name: string;
  role: string;
}

interface Identity {
  id: string;
  email: string | null;
  display_name: string | null;
  organizations: Organization[];
}

interface CaseRecord {
  id: string;
  organization_id: string;
  case_number: string;
  name: string;
  description: string | null;
  status: "open" | "closed";
  created_at: string;
}

const EMPTY_CASES: CaseRecord[] = [];

interface CaseListState {
  organizationId: string;
  cases: CaseRecord[];
  selectedCaseId: string;
}

interface TimelineEvent {
  source_type: "acquisition" | "custody";
  source_record_id: string;
  event_type: string;
  occurred_at: string;
  recorded_at: string;
  evidence_id: string;
  evidence_number: string;
  actor_id: string;
  details: Record<string, unknown>;
  notes: string | null;
}

interface CustodyVerification {
  evidence_id: string;
  valid: boolean;
  event_count: number;
  head_hash: string | null;
}

interface CaseMember {
  user_id: string;
  role: string;
}

interface CaseTimeline {
  case_id: string;
  events: TimelineEvent[];
  custody_verification: CustodyVerification[];
}

interface CaseOverviewState {
  caseId: string;
  identityId: string | null;
  timeline: CaseTimeline | null;
  summaries: AISummary[];
  caseRole: string | null;
  caseError: string;
  summaryError: string;
}

interface SummaryKeyPoint {
  text: string;
  source_record_ids: string[];
}

interface AISummary {
  id: string;
  case_id: string;
  requested_by: string;
  provider: string;
  model_name: string;
  prompt_version: string;
  review_status: string;
  summary: string;
  summary_source_record_ids: string[];
  key_points: SummaryKeyPoint[];
  created_at: string;
}

class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
  ) {
    super(`Request failed: ${status}`);
  }
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    ...init,
  });
  if (!response.ok) {
    throw new ApiError(response.status, path);
  }
  return (await response.json()) as T;
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Your session has expired. Sign in again.";
    if (error.status === 403 || error.status === 404) {
      return "You do not have access to this case.";
    }
    if (error.status === 409) return "This case is closed and cannot be analyzed.";
    if (error.status === 413) return "This case has too many source records to summarize.";
    if (error.status === 502) return "The local AI returned an invalid summary. No draft was saved.";
    if (error.status === 503 && error.path.includes("ai-summaries")) {
      return "Local AI is unavailable or not configured. No draft was saved.";
    }
    return `The API request failed (${error.status}).`;
  }
  return "Could not reach the API. Check the API URL and your connection.";
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function formatLabel(value: string): string {
  return value
    .split(/[_-]/)
    .filter(Boolean)
    .map((part) => part[0].toUpperCase() + part.slice(1))
    .join(" ");
}

function detailText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  return JSON.stringify(value);
}

function CitationLinks({
  sourceIds,
  caseId,
}: {
  sourceIds: string[];
  caseId: string;
}) {
  return (
    <span className="flex flex-wrap gap-2">
      {sourceIds.map((sourceId) => (
        <a
          key={sourceId}
          className="rounded border border-cyan-900 bg-cyan-950/60 px-2 py-1 font-mono text-xs text-cyan-200 hover:border-cyan-500"
          href={`#source-${sourceId}`}
        >
          {sourceId === caseId ? "Case record" : `Source ${sourceId.slice(0, 8)}`}
        </a>
      ))}
    </span>
  );
}

export default function Home() {
  const [authState, setAuthState] = useState<"loading" | "signed-out" | "ready" | "error">(
    "loading",
  );
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [csrfToken, setCsrfToken] = useState("");
  const [selectedOrganizationId, setSelectedOrganizationId] = useState("");
  const [caseList, setCaseList] = useState<CaseListState>({
    organizationId: "",
    cases: [],
    selectedCaseId: "",
  });
  const currentCaseList =
    caseList.organizationId === selectedOrganizationId ? caseList : null;
  const cases = currentCaseList?.cases ?? EMPTY_CASES;
  const selectedCaseId = currentCaseList?.selectedCaseId ?? "";
  const loadingCases = Boolean(selectedOrganizationId) && !currentCaseList;
  const [caseOverview, setCaseOverview] = useState<CaseOverviewState>({
    caseId: "",
    identityId: null,
    timeline: null,
    summaries: [],
    caseRole: null,
    caseError: "",
    summaryError: "",
  });
  const isCurrentCaseOverview =
    caseOverview.caseId === selectedCaseId &&
    caseOverview.identityId === (identity?.id ?? null);
  const currentCaseOverview = isCurrentCaseOverview ? caseOverview : null;
  const {
    timeline = null,
    summaries = [],
    caseRole = null,
    caseError = "",
    summaryError = "",
  } = currentCaseOverview ?? {};
  const loadingCase = Boolean(selectedCaseId) && !isCurrentCaseOverview;
  const [pageError, setPageError] = useState("");

  const selectedCase = useMemo(
    () => cases.find((item) => item.id === selectedCaseId) ?? null,
    [cases, selectedCaseId],
  );
  const selectedOrganizationRole = identity?.organizations.find(
    (organization) => organization.id === selectedOrganizationId,
  )?.role;
  const organizationAdmin =
    selectedOrganizationRole === "owner" || selectedOrganizationRole === "admin";
  const canWriteCase =
    organizationAdmin || caseRole === "owner" || caseRole === "examiner";
  const canReviewCase = organizationAdmin || caseRole === "reviewer";
  const verificationByEvidence = useMemo(
    () =>
      new Map(
        (timeline?.custody_verification ?? []).map((item) => [
          item.evidence_id,
          item,
        ]),
      ),
    [timeline],
  );

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    async function loadIdentity() {
      try {
        const [profile, csrf] = await Promise.all([
          requestJson<Identity>("/auth/me", { signal: controller.signal }),
          requestJson<{ csrf_token: string }>("/auth/csrf", {
            signal: controller.signal,
          }),
        ]);
        if (!active) return;
        setIdentity(profile);
        setCsrfToken(csrf.csrf_token);
        setSelectedOrganizationId(profile.organizations[0]?.id ?? "");
        setPageError("");
        setAuthState("ready");
      } catch (error) {
        if (!active || controller.signal.aborted) return;
        if (error instanceof ApiError && error.status === 401) {
          setAuthState("signed-out");
        } else {
          setPageError(errorMessage(error));
          setAuthState("error");
        }
      }
    }

    void loadIdentity();
    return () => {
      active = false;
      controller.abort();
    };
  }, []);

  useEffect(() => {
    if (!selectedOrganizationId) return;

    const controller = new AbortController();
    let active = true;

    async function loadCases() {
      try {
        const result = await requestJson<CaseRecord[]>(
          `/organizations/${encodeURIComponent(selectedOrganizationId)}/cases`,
          { signal: controller.signal },
        );
        if (!active) return;
        setCaseList({
          organizationId: selectedOrganizationId,
          cases: result,
          selectedCaseId: result[0]?.id ?? "",
        });
      } catch (error) {
        if (!active || controller.signal.aborted) return;
        setPageError(errorMessage(error));
        setCaseList({
          organizationId: selectedOrganizationId,
          cases: [],
          selectedCaseId: "",
        });
      }
    }

    void loadCases();
    return () => {
      active = false;
      controller.abort();
    };
  }, [selectedOrganizationId]);

  useEffect(() => {
    if (!selectedCaseId) return;

    const controller = new AbortController();
    let active = true;

    async function loadCaseOverview() {
      const [timelineResult, summariesResult, membersResult] = await Promise.allSettled([
        requestJson<CaseTimeline>(
          `/cases/${encodeURIComponent(selectedCaseId)}/timeline`,
          { signal: controller.signal },
        ),
        requestJson<AISummary[]>(
          `/cases/${encodeURIComponent(selectedCaseId)}/ai-summaries`,
          { signal: controller.signal },
        ),
        requestJson<CaseMember[]>(
          `/cases/${encodeURIComponent(selectedCaseId)}/members`,
          { signal: controller.signal },
        ),
      ]);
      if (!active) return;
      setCaseOverview({
        caseId: selectedCaseId,
        identityId: identity?.id ?? null,
        timeline:
          timelineResult.status === "fulfilled" ? timelineResult.value : null,
        summaries:
          summariesResult.status === "fulfilled" ? summariesResult.value : [],
        caseRole:
          membersResult.status === "fulfilled" && identity
            ? membersResult.value.find((member) => member.user_id === identity.id)
                ?.role ?? null
            : null,
        caseError:
          timelineResult.status === "rejected"
            ? errorMessage(timelineResult.reason)
            : "",
        summaryError:
          summariesResult.status === "rejected"
            ? errorMessage(summariesResult.reason)
            : "",
      });
    }

    void loadCaseOverview();
    return () => {
      active = false;
      controller.abort();
    };
  }, [identity, selectedCaseId]);

  async function signOut() {
    if (!csrfToken) return;
    setPageError("");
    try {
      const response = await fetch(`${API_BASE_URL}/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: { "X-CSRF-Token": csrfToken },
      });
      if (!response.ok) throw new ApiError(response.status, "/auth/logout");
      setIdentity(null);
      setAuthState("signed-out");
    } catch (error) {
      setPageError(errorMessage(error));
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 md:flex">
      <aside className="border-b border-slate-800 bg-slate-950 p-5 md:min-h-screen md:w-64 md:border-b-0 md:border-r">
        <p className="text-xs font-bold tracking-[0.2em] text-cyan-300">
          AI DIGITAL FORENSICS
        </p>
        <p className="mt-2 text-sm text-slate-500">Investigation workspace</p>
        <nav aria-label="Main navigation" className="mt-8">
          <ul className="flex flex-wrap gap-2 md:flex-col">
            <li>
              <span
                aria-current="page"
                className="block rounded-lg bg-slate-800 px-3 py-2 text-sm text-white"
              >
                Case overview
              </span>
            </li>
            {["Evidence", "Timeline", "Reports"].map((item) => (
              <li key={item}>
                <span
                  aria-disabled="true"
                  className="block rounded-lg px-3 py-2 text-sm text-slate-600"
                >
                  {item} <span className="text-xs">(planned)</span>
                </span>
              </li>
            ))}
          </ul>
        </nav>
        <div className="mt-8 border-t border-slate-800 pt-5">
          <label
            className="block text-xs font-medium uppercase tracking-wide text-slate-500"
            htmlFor="organization-select"
          >
            Organization
          </label>
          <select
            id="organization-select"
            className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 disabled:opacity-50"
            disabled={authState !== "ready" || !identity?.organizations.length}
            value={selectedOrganizationId}
            onChange={(event) => {
              setPageError("");
              setSelectedOrganizationId(event.target.value);
            }}
          >
            {identity?.organizations.map((organization) => (
              <option key={organization.id} value={organization.id}>
                {organization.name}
              </option>
            ))}
          </select>
        </div>
      </aside>

      <section className="min-w-0 flex-1">
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-5 py-5 md:px-8">
          <div>
            <p className="text-xs font-semibold tracking-[0.16em] text-cyan-300">
              CASE MANAGEMENT
            </p>
            <h1 className="mt-1 text-2xl font-semibold text-white">Case overview</h1>
          </div>
          {identity && (
            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-sm font-medium text-slate-200">
                  {identity.display_name ?? "Investigator"}
                </p>
                <p className="text-xs text-slate-500">{identity.email}</p>
              </div>
              <button
                className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-slate-500"
                onClick={() => void signOut()}
                type="button"
              >
                Sign out
              </button>
            </div>
          )}
        </header>

        <div className="mx-auto max-w-7xl space-y-6 p-5 md:p-8">
          {authState === "loading" && (
            <p className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-sm text-slate-400">
              Checking your session…
            </p>
          )}

          {authState === "signed-out" && (
            <section className="rounded-2xl border border-slate-800 bg-slate-900 p-8">
              <p className="text-sm font-semibold text-cyan-300">SECURE WORKSPACE</p>
              <h2 className="mt-3 text-xl font-semibold text-white">Sign in to view cases</h2>
              <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">
                Case records and forensic timelines are available only to
                authenticated, assigned investigators.
              </p>
              <a
                className="mt-6 inline-flex rounded-lg bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-300"
                href={`${API_BASE_URL}/auth/login`}
              >
                Sign in with your organization
              </a>
              <p className="mt-4 text-xs text-slate-500">
                Sign-in requires a configured OIDC provider.
              </p>
            </section>
          )}

          {authState === "error" && (
            <div
              className="rounded-xl border border-rose-900 bg-rose-950/50 p-4 text-sm text-rose-200"
              role="alert"
            >
              {pageError}
            </div>
          )}

          {authState === "ready" && (
            <>
              {pageError && (
                <div
                  className="rounded-xl border border-rose-900 bg-rose-950/50 p-4 text-sm text-rose-200"
                  role="alert"
                >
                  {pageError}
                </div>
              )}

              {!identity?.organizations.length && (
                <section className="rounded-xl border border-slate-800 bg-slate-900 p-6">
                  <h2 className="font-semibold text-white">No organization access</h2>
                  <p className="mt-2 text-sm text-slate-400">
                    Ask an organization owner to add your account before opening a case.
                  </p>
                </section>
              )}

              {!!identity?.organizations.length && (
                <>
                  <section className="flex flex-wrap items-end justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 md:p-6">
                    <div className="min-w-64 flex-1">
                      <p className="text-xs font-semibold tracking-wide text-slate-500">
                        SELECTED CASE
                      </p>
                      <label className="sr-only" htmlFor="case-select">
                        Select a case
                      </label>
                      <select
                        id="case-select"
                        className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-3 text-base font-medium text-white disabled:opacity-50"
                        disabled={loadingCases || cases.length === 0}
                        value={selectedCaseId}
                        onChange={(event) =>
                          setCaseList((current) => ({
                            ...current,
                            selectedCaseId: event.target.value,
                          }))
                        }
                      >
                        {cases.length === 0 ? (
                          <option value="">
                            {loadingCases ? "Loading cases…" : "No assigned cases"}
                          </option>
                        ) : (
                          cases.map((item) => (
                            <option key={item.id} value={item.id}>
                              {item.case_number} · {item.name}
                            </option>
                          ))
                        )}
                      </select>
                    </div>
                    {selectedCase && (
                      <div className="flex items-center gap-2">
                        <span
                          className={`rounded-full px-3 py-1 text-xs font-semibold ${
                            selectedCase.status === "open"
                              ? "bg-emerald-950 text-emerald-300"
                              : "bg-slate-800 text-slate-300"
                          }`}
                        >
                          {formatLabel(selectedCase.status)}
                        </span>
                        <span className="text-xs text-slate-500">
                          Created {formatDate(selectedCase.created_at)}
                        </span>
                      </div>
                    )}
                  </section>

                  {caseError && (
                    <div
                      className="rounded-xl border border-rose-900 bg-rose-950/50 p-4 text-sm text-rose-200"
                      role="alert"
                    >
                      {caseError}
                    </div>
                  )}

                  {selectedCase && (
                    <>
                      <section
                        aria-labelledby="case-heading"
                        className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-4">
                          <div>
                            <p className="font-mono text-sm text-cyan-300">
                              {selectedCase.case_number}
                            </p>
                            <h2
                              className="mt-1 text-xl font-semibold text-white"
                              id={`source-${selectedCase.id}`}
                            >
                              {selectedCase.name}
                            </h2>
                            {selectedCase.description && (
                              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
                                {selectedCase.description}
                              </p>
                            )}
                          </div>
                          <div className="flex flex-wrap gap-2 text-xs">
                            <span className="rounded-lg border border-slate-700 px-3 py-2 text-slate-300">
                              {timeline?.events.length ?? 0} timeline records
                            </span>
                            <span className="rounded-lg border border-slate-700 px-3 py-2 text-slate-300">
                              {summaries.length} AI summaries
                            </span>
                          </div>
                        </div>
                      </section>

                      <EvidenceStoragePanel
                        key={selectedCase.id}
                        canWrite={canWriteCase}
                        caseId={selectedCase.id}
                        caseStatus={selectedCase.status}
                        csrfToken={csrfToken}
                      />

                      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.35fr)_minmax(340px,0.9fr)]">
                        <section
                          aria-labelledby="timeline-heading"
                          className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6"
                        >
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div>
                              <p className="text-xs font-semibold tracking-wide text-cyan-300">
                                EVIDENCE HISTORY
                              </p>
                              <h2
                                className="mt-1 text-lg font-semibold text-white"
                                id="timeline-heading"
                              >
                                Acquisition &amp; custody timeline
                              </h2>
                            </div>
                            <span className="text-xs text-slate-500">
                              Times shown in your local timezone
                            </span>
                          </div>

                          {loadingCase && (
                            <p className="mt-6 text-sm text-slate-400">
                              Loading case records…
                            </p>
                          )}
                          {!loadingCase && timeline?.events.length === 0 && (
                            <p className="mt-6 rounded-xl border border-dashed border-slate-700 p-5 text-sm text-slate-400">
                              No acquisition or custody records are available for this case.
                            </p>
                          )}
                          {!loadingCase && timeline && timeline.events.length > 0 && (
                            <ol className="mt-6 space-y-4">
                              {timeline.events.map((event) => {
                                const verification = verificationByEvidence.get(
                                  event.evidence_id,
                                );
                                return (
                                  <li
                                    className="relative border-l border-slate-700 pl-5"
                                    key={`${event.source_type}-${event.source_record_id}`}
                                  >
                                    <span
                                      aria-hidden="true"
                                      className="absolute -left-1.5 top-1.5 h-3 w-3 rounded-full border-2 border-cyan-400 bg-slate-950"
                                    />
                                    <article
                                      className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"
                                      id={`source-${event.source_record_id}`}
                                    >
                                      <div className="flex flex-wrap items-start justify-between gap-3">
                                        <div>
                                          <h3 className="font-medium text-white">
                                            {formatLabel(event.event_type)}
                                          </h3>
                                          <p className="mt-1 text-xs text-slate-400">
                                            {event.evidence_number} ·{" "}
                                            {formatLabel(event.source_type)}
                                          </p>
                                        </div>
                                        {verification && (
                                          <span
                                            className={`rounded-full px-2.5 py-1 text-xs font-medium ${
                                              verification.valid
                                                ? "bg-emerald-950 text-emerald-300"
                                                : "bg-rose-950 text-rose-300"
                                            }`}
                                          >
                                            {verification.valid
                                              ? "Custody chain verified"
                                              : "Custody chain invalid"}
                                          </span>
                                        )}
                                      </div>
                                      <time
                                        className="mt-3 block text-xs text-slate-500"
                                        dateTime={event.occurred_at}
                                      >
                                        {formatDate(event.occurred_at)}
                                      </time>
                                      <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
                                        {Object.entries(event.details).map(([key, value]) => (
                                          <div key={key}>
                                            <dt className="text-xs text-slate-500">
                                              {formatLabel(key)}
                                            </dt>
                                            <dd className="mt-0.5 break-words text-slate-300">
                                              {detailText(value)}
                                            </dd>
                                          </div>
                                        ))}
                                      </dl>
                                      {event.notes && (
                                        <p className="mt-3 border-t border-slate-800 pt-3 text-sm text-slate-300">
                                          {event.notes}
                                        </p>
                                      )}
                                      <p className="mt-3 font-mono text-[11px] text-slate-600">
                                        Record {event.source_record_id}
                                      </p>
                                    </article>
                                  </li>
                                );
                              })}
                            </ol>
                          )}
                        </section>

                        <section
                          aria-labelledby="ai-summary-heading"
                          className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6"
                        >
                          <p className="text-xs font-semibold tracking-wide text-violet-300">
                            ASSISTED ANALYSIS
                          </p>
                          <h2
                            className="mt-1 text-lg font-semibold text-white"
                            id="ai-summary-heading"
                          >
                            AI case summaries
                          </h2>
                          <p className="mt-3 rounded-lg border border-amber-900/70 bg-amber-950/40 p-3 text-xs leading-5 text-amber-200">
                            AI output is an unreviewed draft, not an examiner finding.
                            Verify each citation before relying on it.
                          </p>
                          {summaryError && (
                            <p
                              className="mt-4 rounded-lg border border-rose-900 bg-rose-950/50 p-3 text-sm text-rose-200"
                              role="alert"
                            >
                              {summaryError}
                            </p>
                          )}
                          {loadingCase && (
                            <p className="mt-5 text-sm text-slate-400">
                              Loading summaries…
                            </p>
                          )}
                          {!loadingCase && summaries.length === 0 && (
                            <p className="mt-5 rounded-xl border border-dashed border-slate-700 p-5 text-sm leading-6 text-slate-400">
                              No AI summaries have been generated for this case.
                              Configure the local Ollama model to create a draft.
                            </p>
                          )}
                          {!loadingCase && summaries.length > 0 && (
                            <div className="mt-5 space-y-4">
                              {summaries.map((summary) => (
                                <article
                                  className="rounded-xl border border-violet-900/60 bg-slate-950/70 p-4"
                                  id={`source-${summary.id}`}
                                  key={summary.id}
                                >
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <span className="rounded-full border border-amber-700/70 bg-amber-950/60 px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide text-amber-200">
                                      {formatLabel(summary.review_status)}
                                    </span>
                                    <time
                                      className="text-xs text-slate-500"
                                      dateTime={summary.created_at}
                                    >
                                      {formatDate(summary.created_at)}
                                    </time>
                                  </div>
                                  <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-200">
                                    {summary.summary}
                                  </p>
                                  <div className="mt-3">
                                    <CitationLinks
                                      caseId={selectedCase.id}
                                      sourceIds={summary.summary_source_record_ids}
                                    />
                                  </div>
                                  {summary.key_points.length > 0 && (
                                    <ul className="mt-4 space-y-3 border-t border-slate-800 pt-4">
                                      {summary.key_points.map((point, index) => (
                                        <li
                                          className="text-sm leading-6 text-slate-300"
                                          key={`${summary.id}-${index}`}
                                        >
                                          <p>{point.text}</p>
                                          <div className="mt-2">
                                            <CitationLinks
                                              caseId={selectedCase.id}
                                              sourceIds={point.source_record_ids}
                                            />
                                          </div>
                                        </li>
                                      ))}
                                    </ul>
                                  )}
                                  <p className="mt-4 border-t border-slate-800 pt-3 text-xs text-slate-500">
                                    {summary.provider} · {summary.model_name} ·{" "}
                                    {summary.prompt_version}
                                  </p>
                                </article>
                              ))}
                            </div>
                          )}
                        </section>
                      </div>
                      <ReportingPanel
                        key={`${selectedCase.id}:${csrfToken}`}
                        canReview={canReviewCase}
                        canWrite={canWriteCase}
                        caseId={selectedCase.id}
                        caseStatus={selectedCase.status}
                        csrfToken={csrfToken}
                        currentUserId={identity?.id ?? ""}
                        sourceOptions={[
                          {
                            id: selectedCase.id,
                            label: `Case ${selectedCase.case_number}`,
                          },
                          ...(timeline?.events ?? []).map((event) => ({
                            id: event.source_record_id,
                            label: `${event.evidence_number} · ${event.event_type}`,
                          })),
                          ...summaries.map((summary) => ({
                            id: summary.id,
                            label: `AI summary · ${formatDate(summary.created_at)}`,
                          })),
                        ]}
                      />
                    </>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </section>
    </main>
  );
}
