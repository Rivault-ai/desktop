import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ScanFace, ArrowRight, CircleAlert, Loader2, KeyRound } from "lucide-react";
import { RivaultLogo } from "@/components/RivaultLogo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";

interface Props {
  onConfigured: () => void;
  initialBaseUrl?: string;
}

type Mode = "default" | "pairing" | "paste";

export default function Setup({ onConfigured, initialBaseUrl }: Props) {
  const [mode, setMode] = useState<Mode>("default");
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState(
    initialBaseUrl ?? "https://api.rivault.ai",
  );
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const startPairing = async () => {
    setMode("pairing");
    setError(null);
    try {
      await invoke("start_pairing", {
        baseUrl: baseUrl.trim() || null,
      });
      onConfigured();
    } catch (err) {
      setError(String(err));
      setMode("default");
    }
  };

  const cancelPairing = async () => {
    try {
      await invoke("cancel_pairing");
    } catch {
      /* best-effort */
    }
    setMode("default");
  };

  const submitPaste = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await invoke("save_config", {
        apiKey: apiKey.trim(),
        baseUrl: baseUrl.trim() || null,
      });
      onConfigured();
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-background text-foreground flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div
          className="flex justify-center mb-10 opacity-0 animate-fade-in"
          style={{ animationDelay: "0ms" }}
        >
          <RivaultLogo size={32} className="text-xl" />
        </div>

        {mode === "default" && (
          <div>
            <div
              className="opacity-0 animate-fade-in-up"
              style={{ animationDelay: "80ms" }}
            >
              <h1 className="text-2xl font-semibold text-center mb-2">
                Welcome to Rivault
              </h1>
              <p className="text-muted-foreground text-sm text-center mb-8">
                Connect this Mac to your vault. The local daemon will redact
                retrieved values from agent transcripts after every task.
              </p>
            </div>

            <div
              className="space-y-3 opacity-0 animate-fade-in-up"
              style={{ animationDelay: "180ms" }}
            >
              <Button
                onClick={startPairing}
                size="lg"
                className="w-full gap-2"
              >
                <ScanFace size={18} />
                Sign in with Rivault
                <ArrowRight size={16} />
              </Button>

              <Button
                onClick={() => setMode("paste")}
                variant="ghost"
                className="w-full text-muted-foreground"
              >
                <KeyRound size={14} />
                Paste an API key instead
              </Button>
            </div>

            {error && (
              <div
                className="mt-4 opacity-0 animate-fade-in-up"
                style={{ animationDelay: "240ms" }}
              >
                <Alert variant="destructive">
                  <CircleAlert size={16} />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              </div>
            )}
          </div>
        )}

        {mode === "pairing" && (
          <div>
            <div
              className="opacity-0 animate-fade-in-up"
              style={{ animationDelay: "0ms" }}
            >
              <h1 className="text-2xl font-semibold text-center mb-2">
                Waiting for browser
              </h1>
              <p className="text-muted-foreground text-sm text-center mb-8">
                Log in with your passkey to finish pairing this Mac.
              </p>
            </div>

            <div
              className="opacity-0 animate-fade-in-up"
              style={{ animationDelay: "80ms" }}
            >
              <Card className="mb-6">
                <CardContent className="p-5">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-full bg-primary/15 border border-primary/20 flex items-center justify-center shrink-0">
                      <Loader2
                        size={18}
                        className="text-primary animate-spin"
                      />
                    </div>
                    <div>
                      <p className="text-sm font-medium">
                        Browser sign-in
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Your browser opened a Rivault tab.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            <div
              className="opacity-0 animate-fade-in-up"
              style={{ animationDelay: "160ms" }}
            >
              {error && (
                <Alert variant="destructive" className="mb-4">
                  <CircleAlert size={16} />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              <Button
                variant="ghost"
                onClick={cancelPairing}
                className="w-full text-muted-foreground"
              >
                Cancel
              </Button>
            </div>
          </div>
        )}

        {mode === "paste" && (
          <div>
            <div
              className="opacity-0 animate-fade-in-up"
              style={{ animationDelay: "0ms" }}
            >
              <h1 className="text-2xl font-semibold text-center mb-2">
                Use an API key
              </h1>
              <p className="text-muted-foreground text-sm text-center mb-8">
                Paste a key from Settings → API keys in your Rivault account.
              </p>
            </div>

            <form
              onSubmit={submitPaste}
              className="space-y-4 opacity-0 animate-fade-in-up"
              style={{ animationDelay: "80ms" }}
            >
              <div className="space-y-2">
                <Label htmlFor="apiKey">API key</Label>
                <Input
                  id="apiKey"
                  type="password"
                  value={apiKey}
                  placeholder="rv_live_…"
                  onChange={(e) => setApiKey(e.target.value)}
                  autoFocus
                  autoComplete="off"
                  spellCheck={false}
                  disabled={submitting}
                />
              </div>

              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                className="text-xs text-muted-foreground hover:text-foreground underline underline-offset-2"
              >
                {showAdvanced ? "Hide advanced" : "Advanced"}
              </button>

              {showAdvanced && (
                <div className="space-y-2">
                  <Label htmlFor="baseUrl">API base URL</Label>
                  <Input
                    id="baseUrl"
                    type="text"
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    disabled={submitting}
                    spellCheck={false}
                  />
                </div>
              )}

              {error && (
                <Alert variant="destructive">
                  <CircleAlert size={16} />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <div className="flex gap-3 pt-2">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    setMode("default");
                    setError(null);
                  }}
                  className="flex-1 text-muted-foreground"
                >
                  Back
                </Button>
                <Button
                  type="submit"
                  disabled={submitting || !apiKey.trim()}
                  className="flex-1 gap-2"
                >
                  {submitting && (
                    <Loader2 size={16} className="animate-spin" />
                  )}
                  {submitting ? "Verifying…" : "Connect"}
                </Button>
              </div>
            </form>
          </div>
        )}

        <p className="text-center text-[11px] text-muted-foreground mt-8 leading-relaxed">
          Your key never leaves this Mac except to call your own Rivault API.
        </p>
      </div>
    </div>
  );
}
