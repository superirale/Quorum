/**
 * What a bunker says when it wants a human before it will do anything.
 *
 * A link rather than a redirect. The URL arrives over the wire from whatever
 * `bunker://` URI was pasted into the connect box, and a page that navigates
 * you somewhere a pasted string chose is a habit worth not teaching — one click
 * is a small price. `noreferrer` for the same reason.
 *
 * Its own file rather than a corner of `App.tsx`, because both the setup screen
 * and the restore screen show it, and `App.tsx` imports the setup screen.
 */

export function AuthPrompt({ url }: { url: string }) {
  return (
    <div className="banner warn">
      <strong>Your signer wants you to approve this connection.</strong>
      <p>
        <a href={url} target="_blank" rel="noreferrer noopener">
          {url}
        </a>
      </p>
      <p className="dim">This page is waiting; it will continue once the signer answers.</p>
    </div>
  )
}
