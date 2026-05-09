// Completion screen for Match Mode — user sees a minimal confirmation after
// verification. Only boolean match results were shared with the service;
// no personal data left the enclave. No consent was required.
//
// The Report button is always present: if something felt wrong during the
// flow (e.g. unexpected document request), the user can flag the policy.

export type CompletionScreenProps = {
  onReport: () => void;
};

export function CompletionScreen({ onReport }: CompletionScreenProps) {
  return (
    <div>
      <h2>Verification complete</h2>
      <p>
        Your identity has been confirmed. No personal data was shared with
        the service.
      </p>
      <button onClick={onReport}>Something wrong? Report</button>
    </div>
  );
}
