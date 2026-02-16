// app/page.tsx
import { getServerInfo } from "@/lib/serverInfo";

export default async function Home() {
  const serverInfo = await getServerInfo();

  return (
    <div style={{ fontFamily: "monospace", padding: "2rem" }}>
      <h1>Server Info (Build Time)</h1>
      <pre>{JSON.stringify(serverInfo, null, 2)}</pre>
    </div>
  );
}
