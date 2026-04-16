/**
 * AUTHENTIX SIGN — Backend Worker
 *
 * Cloudflare Worker + D1 database for B2B organisation management.
 *
 * Endpoints:
 *   POST /auth/register  — Create organisation
 *   POST /auth/login     — Login, returns session token
 *   POST /auth/logout    — Destroy session
 *   GET  /auth/me        — Current org info
 *   GET  /dashboard      — Stats (envois count, contacts count)
 *   POST /envois         — Record a new envoi
 *   GET  /envois         — List envois for current org
 *   POST /destinataires  — Add/update a contact
 *   GET  /destinataires  — List contacts for current org
 *   DELETE /destinataires/:id — Remove a contact
 *   POST /send-invite    — Send HTML invitation email (Brevo) to recipient
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }

    try {
      const path = url.pathname;
      const method = request.method;

      // ── Public routes ─────────────────────────────────────────────
      if (method === 'POST' && path === '/auth/register') return await handleRegister(request, env, cors);
      if (method === 'POST' && path === '/auth/login')    return await handleLogin(request, env, cors);
      if (method === 'GET'  && path === '/auth/confirm')  return await handleConfirm(url, env, cors);

      // ── Authenticated routes ──────────────────────────────────────
      const org = await authenticate(request, env);
      if (!org) return json({ error: 'Non authentifié' }, 401, cors);

      if (method === 'POST' && path === '/auth/logout')     return await handleLogout(request, env, cors);
      if (method === 'GET'  && path === '/auth/me')          return json({ id: org.id, nom: org.nom, email: org.email }, 200, cors);
      if (method === 'GET'  && path === '/dashboard')        return await handleDashboard(org, env, cors);
      if (method === 'POST' && path === '/envois')           return await handleCreateEnvoi(request, org, env, cors);
      if (method === 'GET'  && path === '/envois')           return await handleListEnvois(org, env, cors);
      if (method === 'POST' && path === '/send-invite')      return await handleSendInvite(request, org, env, cors);
      if (method === 'POST' && path === '/send-signing-link') return await handleSendSigningLink(request, org, env, cors);
      if (method === 'POST' && path === '/destinataires')    return await handleCreateDestinataire(request, org, env, cors);
      if (method === 'GET'  && path === '/destinataires')    return await handleListDestinataires(org, env, cors);

      const delMatch = path.match(/^\/destinataires\/(\d+)$/);
      if (method === 'DELETE' && delMatch) return await handleDeleteDestinataire(+delMatch[1], org, env, cors);

      return json({ error: 'Not found' }, 404, cors);
    } catch (e) {
      return json({ error: e.message }, 500, cors);
    }
  },
};

// ── Helpers ──────────────────────────────────────────────────────────

function json(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors },
  });
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateSessionId() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function authenticate(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.substring(7);

  const session = await env.DB.prepare(
    'SELECT org_id, expires_at FROM sessions WHERE id = ?'
  ).bind(token).first();

  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
    return null;
  }

  return await env.DB.prepare('SELECT id, nom, email FROM organisations WHERE id = ?').bind(session.org_id).first();
}

// ── Auth ─────────────────────────────────────────────────────────────

async function handleRegister(request, env, cors) {
  const { nom, email, password, plan } = await request.json();
  if (!nom || !email || !password) return json({ error: 'Champs requis: nom, email, password' }, 400, cors);
  if (password.length < 6) return json({ error: 'Mot de passe : 6 caractères minimum' }, 400, cors);

  const existing = await env.DB.prepare('SELECT id FROM organisations WHERE nom = ?').bind(nom).first();
  if (existing) return json({ error: 'Organisation déjà existante' }, 409, cors);

  const existingEmail = await env.DB.prepare('SELECT id FROM organisations WHERE email = ?').bind(email).first();
  if (existingEmail) return json({ error: 'Email déjà utilisé' }, 409, cors);

  const codeHash = await sha256(password);
  const confirmToken = generateSessionId();
  const chosenPlan = ['gratuit', 'pro', 'entreprise'].includes(plan) ? plan : 'gratuit';

  await env.DB.prepare(
    'INSERT INTO organisations (nom, email, code_hash, plan, confirmed, confirm_token) VALUES (?, ?, ?, ?, 0, ?)'
  ).bind(nom, email, codeHash, chosenPlan, confirmToken).run();

  const org = await env.DB.prepare('SELECT id FROM organisations WHERE nom = ?').bind(nom).first();
  await env.DB.prepare(
    'INSERT INTO users (org_id, email, role) VALUES (?, ?, ?)'
  ).bind(org.id, email, 'admin').run();

  // Send confirmation email (best-effort)
  await sendConfirmEmail(env, email, nom, confirmToken).catch(e => {
    console.log('sendConfirmEmail failed:', e.message);
  });

  return json({ success: true, message: 'Compte créé. Vérifiez votre email pour confirmer.' }, 201, cors);
}

async function handleConfirm(url, env, cors) {
  const token = url.searchParams.get('token');
  console.log('[CONFIRM] Token received:', token ? token.substring(0, 12) + '...' : 'NONE');

  if (!token) return json({ error: 'Token manquant' }, 400, cors);

  // Search: unconsumed token OR already-confirmed org with matching email via a previous token
  let org = await env.DB.prepare(
    'SELECT id, nom, confirmed FROM organisations WHERE confirm_token = ?'
  ).bind(token).first();

  console.log('[CONFIRM] Org found with active token:', org ? org.nom : 'NONE');

  if (!org) {
    // Token was already consumed — check if it matches a recently-confirmed account
    // We keep a trace in a separate column so replays (email scanners, back button) still show success.
    org = await env.DB.prepare(
      'SELECT id, nom, confirmed FROM organisations WHERE last_used_token = ?'
    ).bind(token).first();

    console.log('[CONFIRM] Org found via last_used_token:', org ? org.nom : 'NONE');

    if (!org) return json({ error: 'Token invalide ou expiré' }, 404, cors);
  }

  // First-time confirmation: activate + archive token
  if (!org.confirmed) {
    await env.DB.prepare(
      'UPDATE organisations SET confirmed = 1, last_used_token = confirm_token, confirm_token = NULL WHERE id = ?'
    ).bind(org.id).run();
    console.log('[CONFIRM] Activated org', org.id);
  } else {
    console.log('[CONFIRM] Org already confirmed — showing success page anyway');
  }

  const html = `<!DOCTYPE html><html lang="fr"><head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email confirm\u00e9 \u2014 Authentix Sign</title>
    <style>
      * { box-sizing: border-box; }
      body {
        background: #0c0c0f; color: #f0ece4;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        display: flex; align-items: center; justify-content: center;
        min-height: 100vh; margin: 0; padding: 40px 20px;
      }
      .box { text-align: center; max-width: 520px; width: 100%; }
      .ok { color: #22c55e; font-size: 72px; line-height: 1; margin-bottom: 16px; }
      h1 { color: #c9a84c; font-size: 36px; margin: 0 0 16px; letter-spacing: 1px; }
      p { font-size: 18px; line-height: 1.6; margin: 0 0 16px; color: #f0ece4; }
      strong { color: #c9a84c; }
      .btn {
        display: inline-block; background: #c9a84c; color: #0c0c0f;
        padding: 16px 32px; border-radius: 8px;
        text-decoration: none; font-weight: 700; font-size: 16px;
        letter-spacing: 1px; margin-top: 16px;
      }
      @media (max-width: 600px) {
        body { padding: 24px 16px; }
        .ok { font-size: 56px; }
        h1 { font-size: 28px; }
        p { font-size: 16px; }
        .btn { display: block; width: 100%; font-size: 16px; padding: 16px; }
      }
    </style>
    </head><body><div class="box">
      <div class="ok">\u2713</div>
      <h1>Email confirm\u00e9</h1>
      <p>Votre compte <strong>${org.nom}</strong> est activ\u00e9.</p>
      <p>Vous pouvez maintenant vous connecter pour envoyer des documents.</p>
      <a class="btn" href="https://authentix-sign.tech/?fresh=1">ACC\u00c9DER \u00c0 LA PLATEFORME</a>
    </div></body></html>`;

  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', ...cors } });
}

async function sendConfirmEmail(env, toEmail, orgName, token) {
  console.log('[EMAIL] sendConfirmEmail called for', toEmail);
  const confirmUrl = 'https://authentix-backend.asemantix.workers.dev/auth/confirm?token=' + token;
  const apiKey = env.BREVO_API_KEY;

  console.log('[EMAIL] BREVO_API_KEY present:', !!apiKey, 'length:', apiKey ? apiKey.length : 0);

  if (!apiKey) {
    console.log('[EMAIL] SKIP — BREVO_API_KEY not set');
    return;
  }

  const htmlBody = `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#0c0c0f;color:#f0ece4;">
    <h1 style="color:#c9a84c;text-align:center;">AUTHENTIX SIGN</h1>
    <p>Bonjour,</p>
    <p>Votre organisation <strong>${orgName}</strong> a été créée sur Authentix Sign.</p>
    <p>Cliquez sur le bouton ci-dessous pour confirmer votre email :</p>
    <div style="text-align:center;margin:32px 0;">
      <a href="${confirmUrl}" style="background:#c9a84c;color:#0c0c0f;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:16px;">CONFIRMER MON COMPTE</a>
    </div>
    <p style="color:#a0a0a0;font-size:12px;">Si vous n'avez pas créé ce compte, ignorez cet email.</p>
    <hr style="border:0;border-top:1px solid #2a2a33;margin:24px 0;">
    <p style="color:#a0a0a0;font-size:11px;text-align:center;">Authentix Sign — authentix-sign.tech</p>
  </div>`;

  console.log('[EMAIL] Calling Brevo API for', toEmail);
  const resp = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': apiKey,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      sender: { name: 'AUTHENTIX SIGN', email: 'noreply@authentix-sign.tech' },
      to: [{ email: toEmail, name: orgName }],
      subject: 'Confirmez votre compte Authentix Sign',
      htmlContent: htmlBody,
    }),
  });

  const respText = await resp.text().catch(() => '');
  console.log('[EMAIL] Brevo response:', resp.status, respText);
}

async function handleLogin(request, env, cors) {
  const { nom, code, password } = await request.json();
  const pwd = password || code; // accept both field names
  if (!nom || !pwd) return json({ error: 'Champs requis: nom, mot de passe' }, 400, cors);

  const codeHash = await sha256(pwd);
  const org = await env.DB.prepare(
    'SELECT id, nom, email, confirmed, plan FROM organisations WHERE nom = ? AND code_hash = ?'
  ).bind(nom, codeHash).first();

  if (!org) return json({ error: 'Organisation ou mot de passe incorrect' }, 401, cors);
  if (!org.confirmed) return json({ error: 'Compte non confirmé. Vérifiez votre email.' }, 403, cors);

  const sessionId = generateSessionId();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  await env.DB.prepare(
    'INSERT INTO sessions (id, org_id, expires_at) VALUES (?, ?, ?)'
  ).bind(sessionId, org.id, expiresAt).run();

  return json({ token: sessionId, org: { id: org.id, nom: org.nom, email: org.email, plan: org.plan } }, 200, cors);
}

async function handleLogout(request, env, cors) {
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(auth.substring(7)).run();
  }
  return json({ success: true }, 200, cors);
}

// ── Dashboard ────────────────────────────────────────────────────────

async function handleDashboard(org, env, cors) {
  const envois = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM envois WHERE org_id = ?'
  ).bind(org.id).first();

  const contacts = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM destinataires WHERE org_id = ?'
  ).bind(org.id).first();

  return json({
    envois_total: envois.count,
    contacts_total: contacts.count,
  }, 200, cors);
}

// ── Envois ───────────────────────────────────────────────────────────

async function handleCreateEnvoi(request, org, env, cors) {
  const { destinataire_nom, destinataire_email, doc_hash, doc_name, relay_id, expires_at } = await request.json();
  if (!destinataire_nom || !destinataire_email || !doc_hash) {
    return json({ error: 'Champs requis: destinataire_nom, destinataire_email, doc_hash' }, 400, cors);
  }

  const result = await env.DB.prepare(
    'INSERT INTO envois (org_id, destinataire_nom, destinataire_email, doc_hash, doc_name, relay_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(org.id, destinataire_nom, destinataire_email, doc_hash, doc_name || null, relay_id || null, expires_at || null).run();

  return json({ success: true, id: result.meta.last_row_id }, 201, cors);
}

async function handleListEnvois(org, env, cors) {
  const { results } = await env.DB.prepare(
    'SELECT id, destinataire_nom, destinataire_email, doc_hash, doc_name, statut, created_at FROM envois WHERE org_id = ? ORDER BY created_at DESC LIMIT 100'
  ).bind(org.id).all();

  return json({ envois: results }, 200, cors);
}

// ── Invitation email ─────────────────────────────────────────────────

async function handleSendInvite(request, org, env, cors) {
  const { recipient_name, recipient_email, session } = await request.json();
  console.log('[INVITE] called', { org: org.nom, orgEmail: org.email, recipient_name, recipient_email, session });

  if (!recipient_name || !recipient_email) {
    console.log('[INVITE] FAIL — missing fields');
    return json({ error: 'Champs requis: recipient_name, recipient_email' }, 400, cors);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient_email)) {
    console.log('[INVITE] FAIL — invalid email format');
    return json({ error: 'Email invalide' }, 400, cors);
  }

  const apiKey = env.BREVO_API_KEY;
  console.log('[INVITE] BREVO_API_KEY present:', !!apiKey, 'length:', apiKey ? apiKey.length : 0);
  if (!apiKey) {
    console.log('[INVITE] FAIL — BREVO_API_KEY not configured');
    return json({ error: 'Service email non configuré' }, 503, cors);
  }

  const playStoreUrl = 'https://play.google.com/store/apps/details?id=app.authentixsign';
  const siteUrl = 'https://authentix-sign.tech';
  // URL deep-link : Android avec app installée → ouvre l'app et lit le
  // sender (+ session si présente) ; sans app → tombe sur sign.html.
  const sessionParam = session ? `&session=${encodeURIComponent(session)}` : '';
  const appLink = `${siteUrl}/sign.html?sender=${encodeURIComponent(org.email)}${sessionParam}`;
  const senderOrg = escapeHtml(org.nom);
  const recipName = escapeHtml(recipient_name);
  const safeSenderEmail = escapeHtml(org.email);

  const htmlBody = `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Vous avez un document à signer</title>
</head>
<body style="margin:0;padding:0;background:#0c0c0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#f0ece4;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0c0c0f;padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#14141a;border:1px solid #2a2a33;border-radius:12px;overflow:hidden;">

        <!-- Logo (HTML/CSS — SVG est strippé par Gmail) -->
        <tr><td align="center" style="padding:32px 24px 8px;text-align:center;">
          <table role="presentation" cellpadding="0" cellspacing="0" align="center" style="margin:0 auto;"><tr><td align="center" valign="middle" width="72" height="72" style="width:72px;height:72px;border:3px solid #c9a84c;border-radius:14px;color:#c9a84c;font-size:46px;font-weight:900;font-family:Georgia,'Times New Roman',serif;line-height:1;text-align:center;">A</td></tr></table>
          <h1 style="color:#c9a84c;font-size:26px;letter-spacing:1px;margin:18px 0 0;text-align:center;">AUTHENTIX SIGN</h1>
        </td></tr>

        <!-- Title -->
        <tr><td align="center" style="padding:24px 32px 0;text-align:center;">
          <h2 style="color:#c9a84c;font-size:24px;margin:0 0 16px;text-align:center;font-weight:700;">Vous avez un document à signer</h2>
        </td></tr>

        <!-- Body -->
        <tr><td align="center" style="padding:8px 32px 0;text-align:center;">
          <p style="color:#f0ece4;font-size:16px;line-height:1.6;margin:0 0 16px;text-align:center;">Bonjour ${recipName},</p>
          <p style="color:#f0ece4;font-size:16px;line-height:1.6;margin:0 0 16px;text-align:center;">Si vous recevez ce message, c'est parce que <strong style="color:#c9a84c;">${safeSenderEmail}</strong> vous contacte au nom de <strong style="color:#c9a84c;">${senderOrg}</strong> pour vous faire signer un document de façon cryptographique, inaliénable et sans tiers de confiance.</p>
        </td></tr>

        <!-- CTA Button -->
        <tr><td align="center" style="padding:24px 32px 8px;text-align:center;">
          <table role="presentation" cellpadding="0" cellspacing="0" align="center" style="margin:0 auto;"><tr><td align="center" bgcolor="#c9a84c" style="border-radius:10px;text-align:center;">
            <a href="${appLink}" target="_blank" clicktracking="off" style="display:inline-block;background:#c9a84c;color:#0c0c0f;padding:18px 36px;border-radius:10px;text-decoration:none;font-weight:800;font-size:16px;letter-spacing:1px;">OUVRIR L'APP</a>
          </td></tr></table>
          <p style="color:#a0a0a0;font-size:13px;margin:12px 0 0;text-align:center;">Pas encore installée ? <a href="${playStoreUrl}" target="_blank" clicktracking="off" style="color:#c9a84c;text-decoration:underline;">TÉLÉCHARGER</a></p>
        </td></tr>

        <!-- Instructions -->
        <tr><td align="center" style="padding:24px 32px 0;text-align:center;">
          <p style="color:#c9a84c;font-size:14px;text-transform:uppercase;letter-spacing:1px;margin:0 0 12px;font-weight:700;text-align:center;">Instructions</p>
          <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
            <tr><td align="center" style="color:#f0ece4;font-size:16px;line-height:1.7;padding:6px 0;text-align:center;"><strong style="color:#c9a84c;">1.</strong> Installez l'app <strong>AUTHENTIX SIGN</strong></td></tr>
            <tr><td align="center" style="color:#f0ece4;font-size:16px;line-height:1.7;padding:6px 0;text-align:center;"><strong style="color:#c9a84c;">2.</strong> Ouvrez l'app</td></tr>
            <tr><td align="center" style="color:#f0ece4;font-size:16px;line-height:1.7;padding:6px 0;text-align:center;"><strong style="color:#c9a84c;">3.</strong> Cliquez <strong>MA CLÉ PUBLIQUE</strong> → <strong>PARTAGER</strong></td></tr>
            <tr><td align="center" style="color:#f0ece4;font-size:16px;line-height:1.7;padding:6px 0;text-align:center;"><strong style="color:#c9a84c;">4.</strong> Envoyez votre clé par email à : <a href="mailto:${safeSenderEmail}" style="color:#c9a84c;font-weight:700;text-decoration:none;">${safeSenderEmail}</a></td></tr>
          </table>
        </td></tr>

        <!-- Signature -->
        <tr><td align="center" style="padding:28px 32px 8px;border-top:1px solid #2a2a33;text-align:center;">
          <p style="color:#f0ece4;font-size:16px;line-height:1.6;margin:16px 0 4px;text-align:center;">Cordialement,</p>
          <p style="color:#c9a84c;font-size:16px;font-weight:700;margin:0;text-align:center;">${senderOrg}</p>
        </td></tr>

        <!-- Footer -->
        <tr><td align="center" style="padding:24px 32px 32px;">
          <p style="color:#a0a0a0;font-size:12px;margin:0;">AUTHENTIX SIGN — <a href="${siteUrl}" style="color:#c9a84c;text-decoration:none;">authentix-sign.tech</a></p>
          <p style="color:#a0a0a0;font-size:11px;margin:6px 0 0;">Signature chiffrée de bout en bout</p>
          <p style="color:#6a6a6a;font-size:11px;line-height:1.5;margin:14px 0 0;">
            Vous recevez cet email car <strong style="color:#a0a0a0;">${safeSenderEmail}</strong> vous a explicitement invité à rejoindre AUTHENTIX SIGN pour recevoir un document à signer.<br>
            <a href="mailto:${org.email}?subject=${encodeURIComponent('Désinscription AUTHENTIX SIGN')}&body=${encodeURIComponent('Bonjour, je ne souhaite pas recevoir davantage d\'invitations AUTHENTIX SIGN. Merci de me retirer de votre liste.')}" style="color:#6a6a6a;text-decoration:underline;">Se désinscrire</a>
            &nbsp;·&nbsp;
            <a href="mailto:support@authentix-sign.tech?subject=${encodeURIComponent('Signalement abus AUTHENTIX SIGN')}" style="color:#6a6a6a;text-decoration:underline;">Signaler un abus</a>
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;

  // Unique tag + horodatage dans le sujet — contournent toute dédup
  // côté Brevo anti-abuse ou côté Gmail (threading/spam).
  const uniqueTag = crypto.randomUUID();
  const nowStamp = new Date().toLocaleString('fr-FR', {
    day: '2-digit', month: 'long', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
    timeZone: 'Europe/Paris',
  });
  const subject = `${org.nom} souhaite vous transmettre un document — ${nowStamp}`;

  // Version texte brut — améliore le ratio texte/HTML (anti-spam) et
  // sert de fallback pour les clients mail texte-only.
  const textContent =
`Bonjour ${recipient_name},

Si vous recevez ce message, c'est parce que ${org.email} vous contacte au nom de ${org.nom} pour vous faire signer un document de façon cryptographique, inaliénable et sans tiers de confiance.

Ouvrez l'application AUTHENTIX SIGN :
${appLink}

(Pas encore installée ? Téléchargez-la sur Google Play :
https://play.google.com/store/apps/details?id=app.authentixsign )

Instructions :
1. Installez l'app AUTHENTIX SIGN
2. Ouvrez l'app
3. Cliquez MA CLÉ PUBLIQUE → PARTAGER
4. Envoyez votre clé par email à : ${org.email}

Cordialement,
${org.nom}

---
AUTHENTIX SIGN — https://authentix-sign.tech
Signature chiffrée de bout en bout.

Vous recevez cet email car ${org.email} vous a explicitement invité à rejoindre AUTHENTIX SIGN pour recevoir un document à signer.
Pour vous désinscrire, répondez à cet email avec "STOP" ou écrivez à ${org.email}.`;

  console.log('[INVITE] calling Brevo API for', recipient_email, 'tag:', uniqueTag);
  const resp = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': apiKey,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      sender: { name: 'AUTHENTIX SIGN', email: 'noreply@authentix-sign.tech' },
      to: [{ email: recipient_email, name: recipient_name }],
      replyTo: { email: org.email, name: org.nom },
      subject,
      htmlContent: htmlBody,
      textContent,
      trackClicks: false,
      trackOpens: false,
      tags: [uniqueTag, 'invitation'],
      headers: {
        'X-Mailin-Tag': uniqueTag,
        'X-Entity-Ref-ID': uniqueTag,
        'List-Unsubscribe': `<mailto:${org.email}?subject=Unsubscribe>, <mailto:support@authentix-sign.tech?subject=Unsubscribe>`,
        'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
      },
    }),
  });

  const respText = await resp.text().catch(() => '');
  console.log('[INVITE] Brevo response status:', resp.status, 'body:', respText);

  if (!resp.ok) {
    console.log('[INVITE] FAIL — Brevo returned non-2xx');
    return json({ error: 'Échec envoi email', brevo_status: resp.status, brevo_body: respText }, 502, cors);
  }

  console.log('[INVITE] SUCCESS — email queued for', recipient_email);
  return json({ success: true }, 200, cors);
}

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// ── Signing link email (phase 2 du flux one-shot) ─────────────────────

async function handleSendSigningLink(request, org, env, cors) {
  const { recipient_name, recipient_email, deep_link } = await request.json();
  console.log('[SIGN-LINK] called', { recipient_email, hasLink: !!deep_link });

  if (!recipient_name || !recipient_email || !deep_link) {
    return json({ error: 'Champs requis: recipient_name, recipient_email, deep_link' }, 400, cors);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient_email)) {
    return json({ error: 'Email invalide' }, 400, cors);
  }
  if (!/^https:\/\/authentix-sign\.tech\//.test(deep_link)) {
    return json({ error: 'Lien invalide — doit pointer vers authentix-sign.tech' }, 400, cors);
  }

  const apiKey = env.BREVO_API_KEY;
  if (!apiKey) return json({ error: 'Service email non configuré' }, 503, cors);

  const senderOrg = escapeHtml(org.nom);
  const recipName = escapeHtml(recipient_name);
  const safeLink = escapeHtml(deep_link);
  const uniqueTag = crypto.randomUUID();
  const nowStamp = new Date().toLocaleString('fr-FR', {
    day: '2-digit', month: 'long', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
    timeZone: 'Europe/Paris',
  });
  const subject = `${org.nom} vous envoie un document à signer — ${nowStamp}`;

  const htmlBody = `<!DOCTYPE html>
<html lang="fr"><body style="margin:0;padding:0;background:#0c0c0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#f0ece4;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0c0c0f;padding:40px 16px;"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#14141a;border:1px solid #2a2a33;border-radius:12px;overflow:hidden;">
<tr><td align="center" style="padding:32px 24px 8px;">
<table role="presentation" cellpadding="0" cellspacing="0"><tr><td align="center" style="width:72px;height:72px;">
<svg viewBox="18 18 72 72" width="48" height="48" xmlns="http://www.w3.org/2000/svg"><rect x="20" y="20" width="68" height="68" rx="14" ry="14" fill="none" stroke="#c9a84c" stroke-width="3"/><path fill="#c9a84c" d="M54,28 L34,80 L42,80 L46,68 L62,68 L66,80 L74,80 L54,28 Z M48,60 L54,42 L60,60 Z"/></svg>
</td></tr></table>
<h1 style="color:#c9a84c;font-size:26px;letter-spacing:1px;margin:18px 0 0;">AUTHENTIX SIGN</h1>
</td></tr>
<tr><td style="padding:24px 32px 0;"><h2 style="color:#c9a84c;font-size:24px;margin:0 0 16px;text-align:center;font-weight:700;">Votre document est prêt à signer</h2></td></tr>
<tr><td style="padding:8px 32px 0;">
<p style="color:#f0ece4;font-size:16px;line-height:1.6;margin:0 0 16px;">Bonjour ${recipName},</p>
<p style="color:#f0ece4;font-size:16px;line-height:1.6;margin:0 0 16px;"><strong style="color:#c9a84c;">${senderOrg}</strong> vient de chiffrer votre document avec votre clé publique. Vous êtes la seule personne au monde à pouvoir le déchiffrer et le signer.</p>
</td></tr>
<tr><td align="center" style="padding:24px 32px 8px;">
<table role="presentation" cellpadding="0" cellspacing="0"><tr><td align="center" bgcolor="#c9a84c" style="border-radius:10px;">
<a href="${safeLink}" target="_blank" style="display:inline-block;background:#c9a84c;color:#0c0c0f;padding:18px 36px;border-radius:10px;text-decoration:none;font-weight:800;font-size:16px;letter-spacing:1px;">OUVRIR ET SIGNER</a>
</td></tr></table>
<p style="color:#a0a0a0;font-size:13px;margin:12px 0 0;">Ouvre votre app AUTHENTIX SIGN</p>
</td></tr>
<tr><td style="padding:24px 32px 0;">
<p style="color:#a0a0a0;font-size:14px;line-height:1.6;margin:0 0 8px;">Après signature, <strong style="color:#f0ece4;">${senderOrg}</strong> recevra automatiquement la confirmation avec le certificat .cert.json et le journal horodaté VCH.</p>
</td></tr>
<tr><td style="padding:28px 32px 8px;border-top:1px solid #2a2a33;">
<p style="color:#f0ece4;font-size:16px;line-height:1.6;margin:16px 0 4px;">Cordialement,</p>
<p style="color:#c9a84c;font-size:16px;font-weight:700;margin:0;">${senderOrg}</p>
</td></tr>
<tr><td align="center" style="padding:24px 32px 32px;">
<p style="color:#a0a0a0;font-size:12px;margin:0;">AUTHENTIX SIGN — <a href="${siteUrlStatic}" style="color:#c9a84c;text-decoration:none;">authentix-sign.tech</a></p>
<p style="color:#a0a0a0;font-size:11px;margin:6px 0 0;">Signature chiffrée de bout en bout</p>
</td></tr>
</table></td></tr></table></body></html>`;

  const textContent =
`Bonjour ${recipient_name},

${org.nom} vient de chiffrer votre document avec votre clé publique. Vous êtes la seule personne au monde à pouvoir le déchiffrer et le signer.

Ouvrir et signer :
${deep_link}

Après signature, ${org.nom} recevra automatiquement la confirmation avec le certificat .cert.json et le journal horodaté VCH.

Cordialement,
${org.nom}

---
AUTHENTIX SIGN — https://authentix-sign.tech
Signature chiffrée de bout en bout.`;

  const resp = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'accept': 'application/json', 'api-key': apiKey, 'content-type': 'application/json' },
    body: JSON.stringify({
      sender: { name: 'AUTHENTIX SIGN', email: 'noreply@authentix-sign.tech' },
      to: [{ email: recipient_email, name: recipient_name }],
      replyTo: { email: org.email, name: org.nom },
      subject,
      htmlContent: htmlBody,
      textContent,
      tags: [uniqueTag, 'signing-link'],
      headers: {
        'X-Mailin-Tag': uniqueTag,
        'X-Entity-Ref-ID': uniqueTag,
      },
    }),
  });

  const respText = await resp.text().catch(() => '');
  console.log('[SIGN-LINK] Brevo', resp.status, respText);

  if (!resp.ok) {
    return json({ error: 'Échec envoi email', brevo_status: resp.status, brevo_body: respText }, 502, cors);
  }
  return json({ success: true }, 200, cors);
}

const siteUrlStatic = 'https://authentix-sign.tech';

// ── Destinataires ────────────────────────────────────────────────────

async function handleCreateDestinataire(request, org, env, cors) {
  const { nom, email, cle_publique } = await request.json();
  if (!nom || !email) return json({ error: 'Champs requis: nom, email' }, 400, cors);

  // Upsert: update if same org + email exists
  const existing = await env.DB.prepare(
    'SELECT id FROM destinataires WHERE org_id = ? AND email = ?'
  ).bind(org.id, email).first();

  if (existing) {
    await env.DB.prepare(
      'UPDATE destinataires SET nom = ?, cle_publique = ? WHERE id = ?'
    ).bind(nom, cle_publique || null, existing.id).run();
    return json({ success: true, id: existing.id, updated: true }, 200, cors);
  }

  const result = await env.DB.prepare(
    'INSERT INTO destinataires (org_id, nom, email, cle_publique) VALUES (?, ?, ?, ?)'
  ).bind(org.id, nom, email, cle_publique || null).run();

  return json({ success: true, id: result.meta.last_row_id }, 201, cors);
}

async function handleListDestinataires(org, env, cors) {
  const { results } = await env.DB.prepare(
    'SELECT id, nom, email, cle_publique, date_ajout FROM destinataires WHERE org_id = ? ORDER BY nom'
  ).bind(org.id).all();

  return json({ destinataires: results }, 200, cors);
}

async function handleDeleteDestinataire(id, org, env, cors) {
  const existing = await env.DB.prepare(
    'SELECT id FROM destinataires WHERE id = ? AND org_id = ?'
  ).bind(id, org.id).first();

  if (!existing) return json({ error: 'Destinataire introuvable' }, 404, cors);

  await env.DB.prepare('DELETE FROM destinataires WHERE id = ?').bind(id).run();
  return json({ success: true }, 200, cors);
}
