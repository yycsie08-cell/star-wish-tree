// 星願樹：朋友掛吊飾（不用登入）
// 檢查順序：格式 → 人機驗證（工作量證明）→ 記錄嘗試 → 資料庫函式 hang_insert（限流、容量、寫入）
import { createClient } from "jsr:@supabase/supabase-js@2";
import { checkSolution, sha256, type Solution } from "./pow.ts";

const cors = {
  "Access-Control-Allow-Origin": Deno.env.get("SITE_ORIGIN") ?? "*",
  "Access-Control-Allow-Headers": "content-type, apikey, authorization, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

const ERR: Record<string, [number, string]> = {
  rate_limited: [429, "太頻繁了，等一下再掛"],
  too_many_on_tree: [429, "同一棵樹最多掛 3 個"],
  tree_full: [409, "這棵樹掛滿了"],
  tree_not_found: [404, "找不到這棵樹"],
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "只接受 POST" }, 405);

  let b: Record<string, unknown>;
  try { b = await req.json(); } catch { return json({ error: "格式錯誤" }, 400); }
  const tree = String(b.tree ?? ""), kind = String(b.kind ?? ""), message = String(b.message ?? "").trim();
  const from = b.from == null ? "" : String(b.from).trim();
  const color = Number.isInteger(b.color) ? Number(b.color) : -1;
  if (!/^[0-9a-f-]{36}$/i.test(tree)) return json({ error: "找不到這棵樹" }, 400);
  if (!/^[a-z0-9_]{1,40}$/.test(kind)) return json({ error: "吊飾不正確" }, 400);
  if (color < -1 || color > 7) return json({ error: "顏色不正確" }, 400);
  if (message.length < 1 || message.length > 200) return json({ error: "祝福要 1 到 200 字" }, 400);
  if (from.length > 20) return json({ error: "署名最多 20 字" }, 400);

  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || "unknown";

  // 人機驗證：題目要解對、沒過期、沒被用過
  const why = await checkSolution(b.pow as Solution | undefined);
  if (why) return json({ error: why === "expired" ? "驗證過期了，請再按一次" : "人機驗證沒有通過，請再試一次" }, 403);

  const ipHash = await sha256(ip + (Deno.env.get("IP_SALT") ?? "star-wish-tree"));
  const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
  const used = await db.from("used_challenges").insert({ sig: (b.pow as Solution).signature });
  if (used.error) return json({ error: used.error.code === "23505" ? "這次驗證已經用過了，請再按一次" : "伺服器出錯，等一下再試" }, used.error.code === "23505" ? 403 : 500);
  await db.rpc("hang_note", { p_ip: ipHash }); // 先記錄這次嘗試（被擋下也算）
  const { data, error } = await db.rpc("hang_insert", {
    p_tree: tree, p_kind: kind, p_color: color, p_from: from, p_message: message, p_ip: ipHash,
  });
  if (error) {
    const key = Object.keys(ERR).find((k) => error.message.includes(k));
    if (key) return json({ error: ERR[key][1] }, ERR[key][0]);
    console.error(error);
    return json({ error: "伺服器出錯，等一下再試" }, 500);
  }
  return json({ slot: data });
});
