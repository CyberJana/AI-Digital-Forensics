"use client";

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import ProcessingJobsPanel from "./ProcessingJobsPanel";

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

interface AcquisitionRecord {
  id: string;
  acquisition_method: string;
  source_description: string;
  acquired_at: string;
  recorded_at: string;
}

interface CustodyRecord {
  id: string;
  sequence: number;
  event_type: string;
  notes: string | null;
  event_hash: string;
  recorded_at: string;
}

interface HashVerification {
  id: string;
  submitted_sha256: string;
  matched: boolean;
  checked_at: string;
}

interface ChainVerification {
  valid: boolean;
  event_count: number;
  head_hash: string | null;
}

async function requestJson<T>(
  path: string,
  init?: RequestInit,
  csrfToken?: string,
): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.method && init.method !== "GET" && csrfToken) {
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
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleString();
}

export default function EvidenceIntegrityPanel({
  caseId,
  evidenceId,
  originalSha256,
  csrfToken,
  canWrite,
}: {
  caseId: string;
  evidenceId: string;
  originalSha256: string;
  csrfToken: string;
  canWrite: boolean;
}) {
  const [acquisitions, setAcquisitions] = useState<AcquisitionRecord[]>([]);
  const [custodyEvents, setCustodyEvents] = useState<CustodyRecord[]>([]);
  const [verifications, setVerifications] = useState<HashVerification[]>([]);
  const [chain, setChain] = useState<ChainVerification | null>(null);
  const [eventType, setEventType] = useState("received");
  const [notes, setNotes] = useState("");
  const [submittedHash, setSubmittedHash] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const reload = useCallback(
    async (signal?: AbortSignal) => {
      const base = `/evidence/${encodeURIComponent(evidenceId)}`;
      const [acquisitionResult, custodyResult, verificationResult, chainResult] =
        await Promise.all([
          requestJson<AcquisitionRecord[]>(`${base}/acquisitions`, { signal }),
          requestJson<CustodyRecord[]>(`${base}/custody-events`, { signal }),
          requestJson<HashVerification[]>(`${base}/hash-verifications`, { signal }),
          requestJson<ChainVerification>(`${base}/custody-events/verification`, {
            signal,
          }),
        ]);
      if (!signal?.aborted) {
        setAcquisitions(acquisitionResult);
        setCustodyEvents(custodyResult);
        setVerifications(verificationResult);
        setChain(chainResult);
        setError("");
      }
    },
    [evidenceId],
  );

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        await reload(controller.signal);
      } catch (caught) {
        if (!controller.signal.aborted) {
          setError(caught instanceof Error ? caught.message : "Could not load evidence history.");
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [reload]);

  async function recordCustody(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson(
        `/evidence/${encodeURIComponent(evidenceId)}/custody-events`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ event_type: eventType, notes: notes.trim() || null }),
        },
        csrfToken,
      );
      setNotes("");
      setNotice("Custody event recorded.");
      try {
        await reload();
      } catch (caught) {
        setError(
          `Custody event was recorded, but the history could not be refreshed: ${
            caught instanceof Error ? caught.message : "request failed"
          }`,
        );
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not record custody event.");
    } finally {
      setBusy(false);
    }
  }

  async function verifyHash(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await requestJson<{ matched: boolean }>(
        `/evidence/${encodeURIComponent(evidenceId)}/hash-verifications`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ submitted_sha256: submittedHash.trim().toLowerCase() }),
        },
        csrfToken,
      );
      setSubmittedHash("");
      setNotice(
        result.matched
          ? "Submitted digest matches the registered digest."
          : "Digest mismatch recorded in the custody history.",
      );
      try {
        await reload();
      } catch (caught) {
        setError(
          `Digest comparison was recorded, but the history could not be refreshed: ${
            caught instanceof Error ? caught.message : "request failed"
          }`,
        );
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not verify the digest.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-4 space-y-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
      {error && (
        <p className="rounded-lg border border-rose-900 bg-rose-950/50 p-3 text-sm text-rose-200" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="rounded-lg border border-emerald-900 bg-emerald-950/50 p-3 text-sm text-emerald-200" role="status">
          {notice}
        </p>
      )}
      {loading ? (
        <p className="text-sm text-slate-400">Loading evidence history…</p>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2">
            <section aria-label="Acquisition records">
              <h3 className="text-sm font-semibold text-white">Acquisition</h3>
              {acquisitions.length ? (
                <ul className="mt-2 space-y-2 text-xs text-slate-400">
                  {acquisitions.map((record) => (
                    <li className="rounded border border-slate-800 p-3" key={record.id}>
                      <p className="font-medium text-slate-200">{record.acquisition_method}</p>
                      <p className="mt-1">{record.source_description}</p>
                      <time className="mt-1 block">{formatTime(record.acquired_at)}</time>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 text-xs text-slate-500">No acquisition records.</p>
              )}
            </section>
            <section aria-label="Custody-chain status">
              <h3 className="text-sm font-semibold text-white">Custody-chain verification</h3>
              <p className="mt-2 text-sm text-slate-300">
                {chain?.event_count === 0
                  ? "No events to verify"
                  : chain?.valid
                    ? "Valid"
                    : "Invalid"}{" "}
                · {chain?.event_count ?? 0} events
              </p>
              {chain?.head_hash && (
                <p className="mt-1 break-all font-mono text-[11px] text-slate-500">
                  Head hash: {chain.head_hash}
                </p>
              )}
            </section>
          </div>

          <section aria-label="Custody event history">
            <h3 className="text-sm font-semibold text-white">Custody history</h3>
            {custodyEvents.length ? (
              <ol className="mt-2 space-y-2">
                {custodyEvents.map((event) => (
                  <li
                    className="rounded border border-slate-800 p-3 text-xs"
                    key={event.id}
                  >
                    <div className="flex flex-wrap justify-between gap-2">
                      <span className="font-medium text-slate-200">
                        #{event.sequence} · {event.event_type}
                      </span>
                      <time className="text-slate-500">{formatTime(event.recorded_at)}</time>
                    </div>
                    {event.notes && <p className="mt-1 text-slate-400">{event.notes}</p>}
                    <p className="mt-2 break-all font-mono text-[10px] text-slate-600">
                      {event.event_hash}
                    </p>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="mt-2 text-xs text-slate-500">No custody events.</p>
            )}
          </section>

          <section aria-label="Hash verification history">
            <h3 className="text-sm font-semibold text-white">Hash comparisons</h3>
            <p className="mt-1 break-all font-mono text-[11px] text-slate-500">
              Registered SHA-256: {originalSha256}
            </p>
            <p className="mt-1 text-xs text-amber-200">
              Comparisons use a digest submitted by an investigator; they do not independently verify a source file.
            </p>
            {verifications.length > 0 && (
              <ul className="mt-2 space-y-1 text-xs text-slate-400">
                {verifications.map((verification) => (
                  <li key={verification.id}>
                    {formatTime(verification.checked_at)} ·{" "}
                    {verification.matched ? "match" : "mismatch"} ·{" "}
                    {verification.submitted_sha256}
                  </li>
                ))}
              </ul>
            )}
          </section>

          {canWrite && (
            <div className="grid gap-4 border-t border-slate-800 pt-4 md:grid-cols-2">
              <form className="space-y-2" onSubmit={(event) => void recordCustody(event)}>
                <label className="block text-xs text-slate-400" htmlFor={`custody-type-${evidenceId}`}>
                  Record custody event
                </label>
                <select
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  id={`custody-type-${evidenceId}`}
                  onChange={(event) => setEventType(event.target.value)}
                  value={eventType}
                >
                  {["received", "transferred", "stored", "released", "examined"].map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
                <textarea
                  aria-label="Custody event notes"
                  className="min-h-16 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  maxLength={2000}
                  onChange={(event) => setNotes(event.target.value)}
                  placeholder="Notes (optional)"
                  value={notes}
                />
                <button
                  className="rounded-lg border border-cyan-800 px-3 py-2 text-xs font-medium text-cyan-200 disabled:opacity-50"
                  disabled={busy}
                  type="submit"
                >
                  Record event
                </button>
              </form>

              <form className="space-y-2" onSubmit={(event) => void verifyHash(event)}>
                <label
                  className="block text-xs text-slate-400"
                  htmlFor={`submitted-sha256-${evidenceId}`}
                >
                  Compare submitted SHA-256
                </label>
                <input
                  autoCapitalize="none"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-white"
                  id={`submitted-sha256-${evidenceId}`}
                  maxLength={64}
                  minLength={64}
                  onChange={(event) => setSubmittedHash(event.target.value)}
                  pattern="[a-fA-F0-9]{64}"
                  required
                  value={submittedHash}
                />
                <button
                  className="rounded-lg border border-cyan-800 px-3 py-2 text-xs font-medium text-cyan-200 disabled:opacity-50"
                  disabled={busy}
                  type="submit"
                >
                  Record comparison
                </button>
              </form>
            </div>
          )}
          <ProcessingJobsPanel
            canWrite={canWrite}
            caseId={caseId}
            csrfToken={csrfToken}
            evidenceId={evidenceId}
          />
        </>
      )}
    </div>
  );
}
