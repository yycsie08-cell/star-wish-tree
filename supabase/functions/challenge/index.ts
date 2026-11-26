// 星願樹：發一道人機驗證題目（工作量證明）
import { makeChallenge } from "./pow.ts";

const cors = {
  "Access-Control-Allow-Origin": Deno.env.get("SITE_ORIGIN") ?? "*",
  "Access-Control-Allow-Headers": "content-type, apikey, authorization, x-client-info",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  return new Response(JSON.stringify(await makeChallenge()), {
    headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
});
