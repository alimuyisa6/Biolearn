 import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
);

// Helper to return a JSON response with CORS headers
function jsonResponse(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",          // Or your specific domain
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    },
  });
}

serve(async (req) => {
  // Handle OPTIONS (preflight)
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      },
    });
  }

  // Auth check
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return jsonResponse({ error: "Missing token" }, 401);
  }

  const token = authHeader.split(" ")[1];
  const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token);
  if (authError || !user) {
    return jsonResponse({ error: "Invalid token" }, 401);
  }

  // Admin permission check
  const { data: adminRow } = await supabaseAdmin
    .from("admin_users")
    .select("user_id")
    .eq("user_id", user.id)
    .maybeSingle();

  if (!adminRow) {
    return jsonResponse({ error: "Forbidden – you are not an admin" }, 403);
  }

  // Parse action
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

      return jsonResponse({
        resources: resources ?? 0,
        pendingSubmissions: pendingSubmissions ?? 0,
        users: users?.length ?? 0,
        messages: messages ?? 0,
      });
    } catch (err) {
      return jsonResponse({ error: err.message }, 500);
    }
  }

  // ---------- SUBMISSIONS ----------
  if (req.method === "GET" && action === "submissions") {
    const statusFilter = url.searchParams.get("status");
    let query = supabaseAdmin.from("resource_submissions").select("*").order("created_at", { ascending: false });
    if (statusFilter) query = query.eq("status", statusFilter);
    const { data, error } = await query;
    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse(data);
  }

  // ---------- APPROVE / REJECT ----------
  if (req.method === "POST" && action === "approve") {
    const { submissionId, action: subAction } = await req.json();
    if (!submissionId || !["approve", "reject"].includes(subAction)) {
      return jsonResponse({ error: "Invalid request" }, 400);
    }
    const { data: submission, error: fetchError } = await supabaseAdmin
      .from("resource_submissions")
      .select("*")
      .eq("id", submissionId)
      .single();
    if (fetchError || !submission) return jsonResponse({ error: "Submission not found" }, 404);
    if (submission.status !== "pending") return jsonResponse({ error: "Already processed" }, 400);

    if (subAction === "approve") {
      const { error: insertError } = await supabaseAdmin.from("biology_notes").insert({
        title: submission.title,
        description: submission.description,
        author: submission.author,
        level: submission.level,
        category: submission.category,
        tag: submission.tag,
        file_url: submission.file_url,
        file_size: submission.file_size,
        section_type: submission.level ? `${submission.level} Notes` : "All Resources",
      });
      if (insertError) return jsonResponse({ error: insertError.message }, 500);
    }

    const { error: updateError } = await supabaseAdmin
      .from("resource_submissions")
      .update({ status: subAction === "approve" ? "approved" : "rejected" })
      .eq("id", submissionId);
    if (updateError) return jsonResponse({ error: updateError.message }, 500);

    return jsonResponse({ success: true });
  }

  // ---------- UPLOAD ----------
  if (req.method === "POST" && action === "upload") {
    const { title, description, author, level, category, tag, file_url, file_size } = await req.json();
    if (!title?.trim() || !description?.trim()) {
      return jsonResponse({ error: "Title and description required" }, 400);
    }
    const { error } = await supabaseAdmin.from("biology_notes").insert({
      title: title.trim(),
      description: description.trim(),
      author: author?.trim() || null,
      level: level || null,
      category: category || null,
      tag: tag || null,
      file_url: file_url || null,
      file_size: file_size || null,
      section_type: level ? `${level} Notes` : "All Resources",
    });
    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ success: true }, 201);
  }

  // ---------- USERS ----------
  if (req.method === "GET" && action === "users") {
    const { data: authUsers, error } = await supabaseAdmin.auth.admin.listUsers();
    if (error) return jsonResponse({ error: error.message }, 500);
    const { data: blocked } = await supabaseAdmin.from("blocked_users").select("user_id");
    const blockedIds = new Set((blocked || []).map((b: any) => b.user_id));
    const users = (authUsers.users || []).map((u: any) => ({
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      last_sign_in_at: u.last_sign_in_at,
      blocked: blockedIds.has(u.id),
    }));
    return jsonResponse(users);
  }

  // ---------- BLOCK / UNBLOCK ----------
  if (req.method === "POST" && action === "block") {
    const { userId, block } = await req.json();
    if (!userId || typeof block !== "boolean") return jsonResponse({ error: "Invalid request" }, 400);
    if (block) {
      await supabaseAdmin.from("blocked_users").upsert({ user_id: userId });
    } else {
      await supabaseAdmin.from("blocked_users").delete().eq("user_id", userId);
    }
    return jsonResponse({ success: true });
  }

  // ---------- DELETE USER ----------
  if (req.method === "DELETE" && action === "delete-user") {
    const { userId } = await req.json();
    if (!userId) return jsonResponse({ error: "Missing user ID" }, 400);
    const { error } = await supabaseAdmin.auth.admin.deleteUser(userId);
    if (error) return jsonResponse({ error: error.message }, 500);
    await supabaseAdmin.from("blocked_users").delete().eq("user_id", userId);
    return jsonResponse({ success: true });
  }

  // ---------- NOTIFY ----------
  if (req.method === "POST" && action === "notify") {
    const { message, recipient_all } = await req.json();
    if (!message?.trim()) return jsonResponse({ error: "Message required" }, 400);
    await supabaseAdmin.from("notifications").insert({
      message: message.trim(),
      sender_id: user.id,
      recipient_all: !!recipient_all,
    });
    return jsonResponse({ success: true }, 201);
  }

  // ---------- MESSAGES (contact form) ----------
  if (req.method === "GET" && action === "messages") {
    const { data: messages, error } = await supabaseAdmin
      .from("site_sections")
      .select("*")
      .eq("section", "message")
      .order("created_at", { ascending: false });
    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ messages });
  }

  return jsonResponse({ error: "Unknown action" }, 400);
});
