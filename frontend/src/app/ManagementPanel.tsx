"use client";

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

interface OrganizationMember {
  user_id: string;
  email: string | null;
  display_name: string | null;
  role: string;
}

interface CaseMember {
  user_id: string;
  email: string | null;
  display_name: string | null;
  role: string;
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
    throw new Error(detail);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function messageFrom(error: unknown): string {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

function memberLabel(member: OrganizationMember | CaseMember): string {
  return member.display_name || member.email || member.user_id;
}

export default function ManagementPanel({
  organizationId,
  organizationRole,
  csrfToken,
  caseRecord,
  caseRole,
  onCaseCreated,
  onCaseUpdated,
}: {
  organizationId: string;
  organizationRole: string;
  csrfToken: string;
  caseRecord: CaseRecord | null;
  caseRole: string | null;
  onCaseCreated: (record: CaseRecord) => void;
  onCaseUpdated: (record: CaseRecord) => void;
}) {
  const [organizationMembers, setOrganizationMembers] = useState<OrganizationMember[]>([]);
  const [caseMembers, setCaseMembers] = useState<CaseMember[]>([]);
  const [caseNumber, setCaseNumber] = useState("");
  const [caseName, setCaseName] = useState("");
  const [caseDescription, setCaseDescription] = useState("");
  const [newMemberId, setNewMemberId] = useState("");
  const [newMemberRole, setNewMemberRole] = useState("examiner");
  const [newOrganizationMemberId, setNewOrganizationMemberId] = useState("");
  const [newOrganizationMemberRole, setNewOrganizationMemberRole] = useState("examiner");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const canCreateCase = ["owner", "admin", "examiner"].includes(organizationRole);
  const canManageOrganization = ["owner", "admin"].includes(organizationRole);
  const isOrganizationOwner = organizationRole === "owner";
  const canManageCase = caseRole === "owner" && caseRecord?.status === "open";

  const reloadMembers = useCallback(
    async (signal?: AbortSignal) => {
      if (!organizationId) return;
      const [organizationResult, caseResult] = await Promise.all([
        requestJson<OrganizationMember[]>(
          `/organizations/${encodeURIComponent(organizationId)}/members`,
          csrfToken,
          { signal },
        ),
        caseRecord
          ? requestJson<CaseMember[]>(
              `/cases/${encodeURIComponent(caseRecord.id)}/members`,
              csrfToken,
              { signal },
            )
          : Promise.resolve([]),
      ]);
      if (!signal?.aborted) {
        setOrganizationMembers(organizationResult);
        setCaseMembers(caseResult);
      }
    },
    [caseRecord, csrfToken, organizationId],
  );

  useEffect(() => {
    const controller = new AbortController();
    async function loadMembers() {
      try {
        await reloadMembers(controller.signal);
      } catch (caught) {
        if (!controller.signal.aborted) setError(messageFrom(caught));
      }
    }
    void loadMembers();
    return () => controller.abort();
  }, [reloadMembers]);

  async function createCase(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const record = await requestJson<CaseRecord>(
        `/organizations/${encodeURIComponent(organizationId)}/cases`,
        csrfToken,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            case_number: caseNumber.trim(),
            name: caseName.trim(),
            description: caseDescription.trim() || null,
          }),
        },
      );
      setCaseNumber("");
      setCaseName("");
      setCaseDescription("");
      setNotice("Case created.");
      onCaseCreated(record);
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  async function updateCase(
    changes: Partial<Pick<CaseRecord, "name" | "description" | "status">>,
  ) {
    if (!caseRecord) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const record = await requestJson<CaseRecord>(
        `/cases/${encodeURIComponent(caseRecord.id)}`,
        csrfToken,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(changes),
        },
      );
      setNotice("Case updated.");
      onCaseUpdated(record);
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  async function addCaseMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!caseRecord) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson<CaseMember>(
        `/cases/${encodeURIComponent(caseRecord.id)}/members`,
        csrfToken,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_id: newMemberId, role: newMemberRole }),
        },
      );
      setNewMemberId("");
      await reloadMembers();
      setNotice("Case member assigned.");
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  async function updateCaseMember(userId: string, role: string) {
    if (!caseRecord) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson<CaseMember>(
        `/cases/${encodeURIComponent(caseRecord.id)}/members/${encodeURIComponent(userId)}`,
        csrfToken,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role }),
        },
      );
      await reloadMembers();
      setNotice("Case role updated.");
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  async function removeCaseMember(userId: string) {
    if (
      !caseRecord ||
      !window.confirm("Remove this investigator's access to the case?")
    ) {
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson<void>(
        `/cases/${encodeURIComponent(caseRecord.id)}/members/${encodeURIComponent(userId)}`,
        csrfToken,
        { method: "DELETE" },
      );
      await reloadMembers();
      setNotice("Case member removed.");
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  async function addOrganizationMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson<OrganizationMember>(
        `/organizations/${encodeURIComponent(organizationId)}/members`,
        csrfToken,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            user_id: newOrganizationMemberId,
            role: newOrganizationMemberRole,
          }),
        },
      );
      setNewOrganizationMemberId("");
      await reloadMembers();
      setNotice("Organization member added.");
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  async function updateOrganizationRole(userId: string, role: string) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson<OrganizationMember>(
        `/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}`,
        csrfToken,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role }),
        },
      );
      await reloadMembers();
      setNotice("Organization role updated.");
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  async function removeOrganizationMember(userId: string) {
    if (
      !window.confirm(
        "Remove this user's organization membership? They must have no case assignments.",
      )
    ) {
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson<void>(
        `/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}`,
        csrfToken,
        { method: "DELETE" },
      );
      await reloadMembers();
      setNotice("Organization member removed.");
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      aria-labelledby="management-heading"
      className="space-y-5 rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6"
      id="management-panel"
    >
      <div>
        <p className="text-xs font-semibold tracking-wide text-cyan-300">
          CASE AND ACCESS CONTROLS
        </p>
        <h2 className="mt-1 text-lg font-semibold text-white" id="management-heading">
          Management
        </h2>
      </div>
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

      {canCreateCase && (
        <details className="rounded-xl border border-slate-800 p-4">
          <summary className="cursor-pointer font-medium text-white">Create a case</summary>
          <form className="mt-4 grid gap-3 md:grid-cols-2" onSubmit={(event) => void createCase(event)}>
            <label className="text-xs text-slate-400">
              Case number
              <input
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                maxLength={64}
                onChange={(event) => setCaseNumber(event.target.value)}
                pattern="[A-Za-z0-9._-]+"
                required
                value={caseNumber}
              />
            </label>
            <label className="text-xs text-slate-400">
              Case name
              <input
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                maxLength={200}
                onChange={(event) => setCaseName(event.target.value)}
                required
                value={caseName}
              />
            </label>
            <label className="text-xs text-slate-400 md:col-span-2">
              Description
              <textarea
                className="mt-1 min-h-20 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                maxLength={4000}
                onChange={(event) => setCaseDescription(event.target.value)}
                value={caseDescription}
              />
            </label>
            <button
              className="w-fit rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
              disabled={busy}
              type="submit"
            >
              Create case
            </button>
          </form>
        </details>
      )}

      {caseRecord && (
        <details className="rounded-xl border border-slate-800 p-4">
          <summary className="cursor-pointer font-medium text-white">
            Case settings and assignments
          </summary>
          <div className="mt-4 space-y-5">
            {caseRole === "owner" && (
              <div className="flex flex-wrap gap-2">
                <button
                  className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 disabled:opacity-50"
                  disabled={busy}
                  onClick={() =>
                    void updateCase(
                      caseRecord.status === "open"
                        ? { status: "closed" }
                        : { status: "open" },
                    )
                  }
                  type="button"
                >
                  {caseRecord.status === "open" ? "Close case" : "Reopen case"}
                </button>
              </div>
            )}
            <ul className="divide-y divide-slate-800">
              {caseMembers.map((member) => (
                <li
                  className="flex flex-wrap items-center justify-between gap-3 py-3"
                  key={member.user_id}
                >
                  <div>
                    <p className="text-sm font-medium text-white">{memberLabel(member)}</p>
                    <p className="text-xs text-slate-500">
                      {member.email} · {member.role}
                    </p>
                  </div>
                  {canManageCase && (
                    <div className="flex items-center gap-2">
                      <select
                        aria-label={`Role for ${memberLabel(member)}`}
                        className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-white"
                        disabled={busy}
                        onChange={(event) =>
                          void updateCaseMember(member.user_id, event.target.value)
                        }
                        value={member.role}
                      >
                        {["owner", "examiner", "reviewer", "viewer"].map((role) => (
                          <option key={role} value={role}>
                            {role}
                          </option>
                        ))}
                      </select>
                      <button
                        className="rounded border border-rose-900 px-2 py-1 text-xs text-rose-200 disabled:opacity-50"
                        disabled={busy}
                        onClick={() => void removeCaseMember(member.user_id)}
                        type="button"
                      >
                        Remove
                      </button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
            {canManageCase && caseRecord.status === "open" && (
              <form className="flex flex-wrap gap-2" onSubmit={(event) => void addCaseMember(event)}>
                <select
                  aria-label="Organization member to assign"
                  className="min-w-52 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  onChange={(event) => setNewMemberId(event.target.value)}
                  required
                  value={newMemberId}
                >
                  <option value="">Select organization member</option>
                  {organizationMembers
                    .filter(
                      (member) =>
                        !caseMembers.some((assigned) => assigned.user_id === member.user_id),
                    )
                    .map((member) => (
                      <option key={member.user_id} value={member.user_id}>
                        {memberLabel(member)}
                      </option>
                    ))}
                </select>
                <select
                  aria-label="Case role"
                  className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  onChange={(event) => setNewMemberRole(event.target.value)}
                  value={newMemberRole}
                >
                  {["examiner", "reviewer", "viewer"].map((role) => (
                    <option key={role} value={role}>
                      {role}
                    </option>
                  ))}
                </select>
                <button
                  className="rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
                  disabled={busy || !newMemberId}
                  type="submit"
                >
                  Assign member
                </button>
              </form>
            )}
          </div>
        </details>
      )}

      <details className="rounded-xl border border-slate-800 p-4">
        <summary className="cursor-pointer font-medium text-white">
          Organization members ({organizationMembers.length})
        </summary>
        <p className="mt-3 text-xs leading-5 text-slate-500">
          Users must sign in once before an owner or admin can add them. Membership requires their user ID.
        </p>
        <ul className="mt-2 divide-y divide-slate-800">
          {organizationMembers.map((member) => (
            <li
              className="flex flex-wrap items-center justify-between gap-3 py-3"
              key={member.user_id}
            >
              <div>
                <p className="text-sm font-medium text-white">{memberLabel(member)}</p>
                <p className="text-xs text-slate-500">
                  {member.email} · {member.role}
                </p>
              </div>
              {isOrganizationOwner && (
                <div className="flex items-center gap-2">
                  <select
                    aria-label={`Organization role for ${memberLabel(member)}`}
                    className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-white"
                    disabled={busy}
                    onChange={(event) =>
                      void updateOrganizationRole(member.user_id, event.target.value)
                    }
                    value={member.role}
                  >
                    {["owner", "admin", "examiner", "reviewer", "viewer"].map((role) => (
                      <option key={role} value={role}>
                        {role}
                      </option>
                    ))}
                  </select>
                  <button
                    className="rounded border border-rose-900 px-2 py-1 text-xs text-rose-200 disabled:opacity-50"
                    disabled={busy}
                    onClick={() => void removeOrganizationMember(member.user_id)}
                    type="button"
                  >
                    Remove
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
        {canManageOrganization && (
          <form
            className="mt-4 flex flex-wrap gap-2"
            onSubmit={(event) => void addOrganizationMember(event)}
          >
            <label className="sr-only" htmlFor="organization-member-id">
              User ID to add
            </label>
            <input
              className="min-w-64 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              id="organization-member-id"
              onChange={(event) => setNewOrganizationMemberId(event.target.value)}
              placeholder="User ID"
              required
              value={newOrganizationMemberId}
            />
            <select
              aria-label="Organization role"
              className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              onChange={(event) => setNewOrganizationMemberRole(event.target.value)}
              value={newOrganizationMemberRole}
            >
              {["examiner", "reviewer", "viewer", ...(isOrganizationOwner ? ["admin"] : [])].map(
                (role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ),
              )}
            </select>
            <button
              className="rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
              disabled={busy || !newOrganizationMemberId.trim()}
              type="submit"
            >
              Add member
            </button>
          </form>
        )}
      </details>
      {!canManageOrganization && !canCreateCase && !caseRecord && (
        <p className="text-sm text-slate-500">You have read-only access to this organization.</p>
      )}
    </section>
  );
}
