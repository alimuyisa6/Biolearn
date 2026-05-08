 import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!   // service role for admin operations
);

serve(async (req) => {
  // ── CORS headers (allow your domain) ──
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",   // or your exact domain
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      },
    });
  }

  // ── Auth check ──
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Missing token" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }

  const token = authHeader.split(" ")[1];
  const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token);
  if (authError || !user) {
    return new Response(JSON.stringify({ error: "Invalid token" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }

  // ── Admin permission check ──
  const { data: adminRow } = await supabaseAdmin
    .from("admin_users")
    .select("user_id")
    .eq("user_id", user.id)
    .maybeSingle();

  if (!adminRow) {
    return new Response(JSON.stringify({ error: "Forbidden – you are not an admin" }), {
      status: 403,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }

  // ── Parse action ──
  const url = new URL(req.url);
  const action = url.searchParams.get("action");

  // ---------- STATS ----------
  if (req.method === "GET" && action === "stats") {
    try {
      const [{ count: resources }, { count: pendingSubmissions }, { count: messages }] =
        await Promise.all([
          supabaseAdmin.from("biology_notes").select("*", { count: "exact", head: true }),
          supabaseAdmin.from("resource_submissions").select("*", { count: "exact", head: true }).eq("status", "pending"),
          supabaseAdmin.from("site_sections").select("*", { count: "exact", head: true }).eq("section", "message"),
        ]);
      const { data: { users }, error: userError } = await supabaseAdmin.auth.admin.listUsers();
      if (userError) throw userError;

      return new Response(JSON.stringify({
        resources: resources ?? 0,
        pendingSubmissions: pendingSubmissions ?? 0,
        users: users?.length ?? 0,
        messages: messages ?? 0,
      }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }
  }

  // ---------- SUBMISSIONS ----------
  if (req.method === "GET" && action === "submissions") {
    const statusFilter = url.searchParams.get("status");
    let query = supabaseAdmin.from("resource_submissions").select("*").order("created_at", { ascending: false });
    if (statusFilter) query = query.eq("status", statusFilter);
    const { data, error } = await query;
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
  }

  // ---------- APPROVE / REJECT ----------
  if (req.method === "POST" && action === "approve") {
    const { submissionId, action: subAction } = await req.json();
    if (!submissionId || !["approve", "reject"].includes(subAction)) {
      return new Response(JSON.stringify({ error: "Invalid request" }), { status: 400, headers: { ... } });
    }
    const { data: submission, error: fetchError } = await supabaseAdmin
      .from("resource_submissions").select("*").eq("id", submissionId).single();
    if (fetchError || !submission) return new Response(JSON.stringify({ error: "Submission not found" }), { status: 404 });
    if (submission.status !== "pending") return new Response(JSON.stringify({ error: "Already processed" }), { status: 400 });

    if (subAction === "approve") {
      const { error: insertError } = await supabaseAdmin.from("biology_notes").insert({
        title: submission.title, description: submission.description, author: submission.author,
        level: submission.level, category: submission.category, tag: submission.tag,
        file_url: submission.file_url, file_size: submission.file_size,
        section_type: submission.level ? `${submission.level} Notes` : "All Resources",
      });
      if (insertError) return new Response(JSON.stringify({ error: insertError.message }), { status: 500 });
    }

    const { error: updateError } = await supabaseAdmin
      .from("resource_submissions")
      .update({ status: subAction === "approve" ? "approved" : "rejected" })
      .eq("id", submissionId);
    if (updateError) return new Response(JSON.stringify({ error: updateError.message }), { status: 500 });

    return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
  }

  // ---------- UPLOAD ----------
  if (req.method === "POST" && action === "upload") {
    const { title, description, author, level, category, tag, file_url, file_size } = await req.json();
    if (!title?.trim() || !description?.trim()) {
      return new Response(JSON.stringify({ error: "Title and description required" }), { status: 400 });
    }
    const { error } = await supabaseAdmin.from("biology_notes").insert({
      title: title.trim(), description: description.trim(), author: author?.trim() || null,
      level: level || null, category: category || null, tag: tag || null,
      file_url: file_url || null, file_size: file_size || null,
      section_type: level ? `${level} Notes` : "All Resources",
    });
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500 });
    return new Response(JSON.stringify({ success: true }), { status: 201, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
  }

  // ---------- USERS ----------
  if (req.method === "GET" && action === "users") {
    const { data: authUsers, error } = await supabaseAdmin.auth.admin.listUsers();
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500 });
    const { data: blocked } = await supabaseAdmin.from("blocked_users").select("user_id");
    const blockedIds = new Set((blocked || []).map((b: any) => b.user_id));
    const users = (authUsers.users || []).map((u: any) => ({
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      last_sign_in_at: u.last_sign_in_at,
      blocked: blockedIds.has(u.id),
    }));
    return new Response(JSON.stringify(users), { headers: { ... } });
  }

  // ---------- BLOCK / UNBLOCK ----------
  if (req.method === "POST" && action === "block") {
    const { userId, block } = await req.json();
    if (!userId || typeof block !== "boolean") return new Response(JSON.stringify({ error: "Invalid request" }), { status: 400 });
    if (block) {
      await supabaseAdmin.from("blocked_users").upsert({ user_id: userId });
    } else {
      await supabaseAdmin.from("blocked_users").delete().eq("user_id", userId);
    }
    return new Response(JSON.stringify({ success: true }), { headers: { ... } });
  }

  // ---------- DELETE USER ----------
  if (req.method === "DELETE" && action === "delete-user") {
    const { userId } = await req.json();
    if (!userId) return new Response(JSON.stringify({ error: "Missing user ID" }), { status: 400 });
    const { error } = await supabaseAdmin.auth.admin.deleteUser(userId);
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500 });
    await supabaseAdmin.from("blocked_users").delete().eq("user_id", userId);
    return new Response(JSON.stringify({ success: true }), { headers: { ... } });
  }

  // ---------- NOTIFY ----------
  if (req.method === "POST" && action === "notify") {
    const { message, recipient_all } = await req.json();
    if (!message?.trim()) return new Response(JSON.stringify({ error: "Message required" }), { status: 400 });
    await supabaseAdmin.from("notifications").insert({
      message: message.trim(),
      sender_id: user.id,
      recipient_all: !!recipient_all,
    });
    return new Response(JSON.stringify({ success: true }), { status: 201 });
  }

  // ---------- MESSAGES (contact form) ----------
  if (req.method === "GET" && action === "messages") {
    const { data: messages, error } = await supabaseAdmin
      .from("site_sections")
      .select("*")
      .eq("section", "message")
      .order("created_at", { ascending: false });
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500 });
    return new Response(JSON.stringify({ messages }), { headers: { ... } });
  }

  return new Response(JSON.stringify({ error: "Unknown action" }), { status: 400 });
});
