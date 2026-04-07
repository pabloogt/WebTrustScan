type UrlFormProps = {
  url: string;
  loading: boolean;
  errorMessage: string;
  onUrlChange: (value: string) => void;
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => void;
};

export default function UrlForm({
  url,
  loading,
  errorMessage,
  onUrlChange,
  onSubmit,
}: UrlFormProps) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl">
      <form onSubmit={onSubmit} className="flex flex-col sm:flex-row gap-4">
        <input
          type="text"
          value={url}
          onChange={(e) => onUrlChange(e.target.value)}
          placeholder="https://tuweb.com"
          className="flex-1 rounded-xl bg-slate-800 border border-slate-700 px-4 py-3 text-white placeholder:text-slate-400 outline-none focus:border-slate-500"
        />
        <button
          type="submit"
          disabled={loading}
          className="rounded-xl bg-white text-slate-900 font-semibold px-6 py-3 hover:bg-slate-200 transition disabled:opacity-60"
        >
          {loading ? "Analizando..." : "Analizar"}
        </button>
      </form>

      <p className="mt-4 text-sm text-slate-400">
        Revisamos HTTPS, redirecciones y cabeceras básicas de seguridad.
      </p>

      {errorMessage && (
        <div className="mt-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {errorMessage}
        </div>
      )}
    </div>
  );
}