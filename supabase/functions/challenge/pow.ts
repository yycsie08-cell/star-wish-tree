// 人機驗證：工作量證明（Proof of Work，作法同開源的 ALTCHA）
// 伺服器出題：salt + 隨機數字 n 的 SHA-256；瀏覽器要從 0 開始試，找出 n 才能送出。
// 題目用 HMAC 簽名，不能自己偽造；10 分鐘過期；每題只能用一次（used_challenges）。
export const MAXNUM = 40000;

const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export const sha256 = async (s: string) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));

async function hmac(s: string) {
  const base = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!base) throw new Error("缺少 SUPABASE_SERVICE_ROLE_KEY，不能簽題目"); // 沒有私密金鑰就不出題，避免被偽造
  const secret = base + ":star-wish-tree-pow";
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(s)));
}

export async function makeChallenge() {
  const rand = new Uint8Array(12); crypto.getRandomValues(rand);
  const salt = hex(rand.buffer) + "?expires=" + Math.floor(Date.now() / 1000 + 600);
  const n = Math.floor(Math.random() * MAXNUM);
  const challenge = await sha256(salt + n);
  return { algorithm: "SHA-256", challenge, maxnumber: MAXNUM, salt, signature: await hmac(challenge) };
}

export type Solution = { salt: string; number: number; challenge: string; signature: string };

// 回傳 null 表示通過，否則回傳原因
export async function checkSolution(p: Solution | undefined): Promise<string | null> {
  if (!p || typeof p.salt !== "string" || typeof p.challenge !== "string" || typeof p.signature !== "string" || !Number.isInteger(p.number)) return "missing";
  const exp = Number(new URLSearchParams(p.salt.split("?")[1] ?? "").get("expires"));
  if (!exp || exp < Date.now() / 1000) return "expired";
  if ((await sha256(p.salt + p.number)) !== p.challenge) return "wrong";
  if ((await hmac(p.challenge)) !== p.signature) return "forged";
  return null;
}
