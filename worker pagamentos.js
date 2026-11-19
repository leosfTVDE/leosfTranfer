// Trajeto Transfer — serviço de pagamentos (Cloudflare Worker)
// Fase 1: cobranças na conta Stripe do dono da app (sem taxa da app).
// Fase 2 (MODO = "plataforma"): cada motorista ativa a sua conta (Stripe Connect Express);
//         o dinheiro vai para ele e a app fica com uma taxa por pagamento online
//         (percentagem com mínimo e máximo), exceto para quem tem o plano PRO.
//
// Variáveis (Cloudflare → Worker → Settings → Variables and Secrets):
//   STRIPE_SECRET     (secret)  chave da Stripe — NUNCA a envies a ninguém
//   DONO_EMAIL        e-mail com que entras no Trajeto (o dono da app)
//   FIREBASE_PROJECT  trajeto-app
//   MODO              proprio   (fase 1)  ·  plataforma  (fase 2)
//   TAXA_PCT          5         (percentagem da taxa da app, fase 2)
//   TAXA_MIN          0.30      (taxa mínima em €)
//   TAXA_MAX          1.50      (taxa máxima em €)
//   PRO_PRICE_ID      price_…   (preço mensal do plano PRO, criado na Stripe — fase 2)
//   PRO_TEXTO         €9,99/mês
//   PRO_PRECO         9.99
//   APP_URL           https://…/  (endereço do Trajeto, para voltar da Stripe)
// Opcional (fase 2): KV namespace ligado como CONTAS (guarda motorista → conta Stripe)

const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
let jwksCache = null, jwksAte = 0;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400'
};
function json(obj, status = 200){ return new Response(JSON.stringify(obj), { status, headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8' } }); }
function erro(msg, status = 400){ return json({ erro: msg }, status); }

// ---------- verificação do login do Trajeto (token do Firebase) ----------
function b64urlBytes(s){ s = s.replace(/-/g, '+').replace(/_/g, '/'); while(s.length % 4) s += '='; const b = atob(s); const u = new Uint8Array(b.length); for(let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
function b64urlJson(s){ return JSON.parse(new TextDecoder().decode(b64urlBytes(s))); }
async function chaves(){
  if(jwksCache && Date.now() < jwksAte) return jwksCache;
  const r = await fetch(JWKS_URL);
  if(!r.ok) throw new Error('jwks');
  const j = await r.json();
  const m = /max-age=(\d+)/.exec(r.headers.get('cache-control') || '');
  jwksCache = j.keys || []; jwksAte = Date.now() + (m ? +m[1] : 3600) * 1000;
  return jwksCache;
}
async function verificarToken(req, env){
  const h = req.headers.get('Authorization') || '';
  const tk = h.startsWith('Bearer ') ? h.slice(7) : '';
  const p = tk.split('.');
  if(p.length !== 3) return null;
  let cab, dados;
  try{ cab = b64urlJson(p[0]); dados = b64urlJson(p[1]); }catch(e){ return null; }
  if(cab.alg !== 'RS256') return null;
  const proj = env.FIREBASE_PROJECT || 'trajeto-app', agora = Math.floor(Date.now() / 1000);
  if(dados.aud !== proj || dados.iss !== 'https://securetoken.google.com/' + proj) return null;
  if(!(dados.exp > agora) || !(dados.iat <= agora + 300) || !dados.sub) return null;
  const jwk = (await chaves()).find(k => k.kid === cab.kid);
  if(!jwk) return null;
  const chave = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', chave, b64urlBytes(p[2]), new TextEncoder().encode(p[0] + '.' + p[1]));
  if(!ok) return null;
  return { uid: dados.sub, email: String(dados.email || '').toLowerCase() };
}

// ---------- Stripe ----------
function form(obj, pre = '', out = []){
  for(const [k, v] of Object.entries(obj)){
    if(v === undefined || v === null || v === '') continue;
    const chave = pre ? `${pre}[${k}]` : k;
    if(typeof v === 'object') form(v, chave, out);
    else out.push(encodeURIComponent(chave) + '=' + encodeURIComponent(String(v)));
  }
  return out;
}
async function stripe(env, metodo, caminho, params, conta){
  const h = { 'Authorization': 'Bearer ' + env.STRIPE_SECRET, 'Stripe-Version': '2024-06-20' };
  if(conta) h['Stripe-Account'] = conta;
  let url = 'https://api.stripe.com/v1' + caminho, body;
  if(params){
    const q = form(params).join('&');
    if(metodo === 'GET') url += (url.includes('?') ? '&' : '?') + q;
    else { body = q; h['Content-Type'] = 'application/x-www-form-urlencoded'; }
  }
  const r = await fetch(url, { method: metodo, headers: h, body });
  const j = await r.json().catch(() => ({}));
  if(!r.ok){ const e = new Error((j.error && j.error.message) || 'Stripe ' + r.status); e.stripe = true; throw e; }
  return j;
}

// ---------- regras ----------
function taxaCfg(env){
  const c = v => Math.round(parseFloat(String(v || '0').replace(',', '.')) * 100) || 0;
  return { pct: parseFloat(String(env.TAXA_PCT || '5').replace(',', '.')) || 0, minC: c(env.TAXA_MIN || '0.30'), maxC: c(env.TAXA_MAX || '1.50') };
}
export function taxaAppCent(valorC, t){
  if(!t || !(t.pct > 0) || !(valorC > 0)) return 0;
  let x = Math.round(valorC * t.pct / 100);
  if(t.minC) x = Math.max(t.minC, x);
  if(t.maxC) x = Math.min(t.maxC, x);
  return Math.min(x, valorC);
}
function ehDono(u, env){ return !!(u && u.email && env.DONO_EMAIL && u.email === String(env.DONO_EMAIL).trim().toLowerCase()); }
function plataforma(env){ return String(env.MODO || 'proprio').trim().toLowerCase() === 'plataforma'; }
function proCfg(env){ return { disponivel: !!env.PRO_PRICE_ID, texto: env.PRO_TEXTO || '€9,99/mês', precoC: Math.round(parseFloat(String(env.PRO_PRECO || '9.99').replace(',', '.')) * 100) || 0 }; }

// conta Stripe do motorista: KV (se existir) ou a que a app envia, confirmada pelos metadados
async function contaDoMotorista(env, u, contaPedida){
  let id = '';
  if(env.CONTAS) id = (await env.CONTAS.get(u.uid)) || '';
  if(!id && contaPedida && /^acct_[A-Za-z0-9]+$/.test(contaPedida)) id = contaPedida;
  if(!id) return null;
  try{
    const a = await stripe(env, 'GET', '/accounts/' + id);
    if(!a.metadata || a.metadata.trajeto_uid !== u.uid) return null;
    return a;
  }catch(e){ return null; }
}
async function assinaturaPro(env, u){
  if(!env.PRO_PRICE_ID) return null;
  const r = await stripe(env, 'GET', '/subscriptions/search', { query: `status:'active' AND metadata['trajeto_uid']:'${u.uid.replace(/'/g, '')}'` });
  return (r.data && r.data[0]) || null;
}

function voltarUrl(env, pedido, extra){
  let base = String((pedido && /^https:\/\//.test(pedido) ? pedido : env.APP_URL) || '').split('?')[0];
  if(!base) base = 'https://example.com/';
  return base + '?pagamentos=' + extra;
}

function paginaObrigado(lang){
  const en = lang === 'en';
  const html = `<!doctype html><html lang="${en ? 'en' : 'pt'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${en ? 'Payment received' : 'Pagamento recebido'}</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f2ead8;font-family:-apple-system,'Helvetica Neue',Arial,sans-serif;color:#0d1b2a;text-align:center;padding:24px;box-sizing:border-box}
.c{background:#fffdf8;border:1px solid #eadfc8;border-radius:22px;padding:34px 26px;max-width:380px}.i{font-size:54px}h1{font-size:24px;margin:10px 0 6px}p{color:#5d6670;line-height:1.5}</style></head>
<body><div class="c"><div class="i">✅</div><h1>${en ? 'Payment received' : 'Pagamento recebido'}</h1><p>${en ? 'Thank you! Your payment was confirmed. You can close this page.' : 'Obrigado! O seu pagamento foi confirmado. Pode fechar esta página.'}</p></div></body></html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

export default {
  async fetch(req, env){
    const url = new URL(req.url), caminho = url.pathname.replace(/\/+$/, '') || '/';
    if(req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if(caminho === '/obrigado') return paginaObrigado(url.searchParams.get('l'));
    if(caminho === '/') return json({ ok: true, servico: 'trajeto-pagamentos', modo: plataforma(env) ? 'plataforma' : 'proprio' });
    if(!env.STRIPE_SECRET) return erro('O serviço de pagamentos ainda não tem a chave da Stripe.', 500);

    let u;
    try{ u = await verificarToken(req, env); }catch(e){ return erro('Não foi possível confirmar o login. Tenta outra vez.', 503); }
    if(!u) return erro('Sessão inválida: volta a entrar no Trajeto.', 401);

    const dono = ehDono(u, env), modoPlat = plataforma(env);
    if(!dono && !modoPlat) return erro('Os pagamentos online ainda não estão disponíveis para a tua conta.', 403);
    let corpo = {};
    if(req.method === 'POST'){ try{ corpo = await req.json(); }catch(e){ corpo = {}; } }

    try{
      // ---- informação para o painel ----
      if(caminho === '/eu'){
        const t = taxaCfg(env), pro = proCfg(env);
        if(dono){
          let nomeConta = '';
          try{ const a = await stripe(env, 'GET', '/account'); nomeConta = (a.settings && a.settings.dashboard && a.settings.dashboard.display_name) || (a.business_profile && a.business_profile.name) || ''; }catch(e){}
          return json({ modo: modoPlat ? 'plataforma' : 'proprio', dono: true, nomeConta, taxa: { pct: 0, minC: 0, maxC: 0 }, taxaPlataforma: t, proPlataforma: pro, pro: { disponivel: false } });
        }
        const a = await contaDoMotorista(env, u, url.searchParams.get('conta'));
        const sub = await assinaturaPro(env, u).catch(() => null);
        return json({ modo: 'plataforma', dono: false, taxa: t, pro: { ...pro, ativo: !!sub },
          conta: a ? { id: a.id, ativa: !!a.charges_enabled, detalhes: !!a.details_submitted } : {} });
      }

      // ---- criar cobrança (link + QR) ----
      if(caminho === '/cobrar' && req.method === 'POST'){
        const valorC = Math.round(+corpo.valorC);
        if(!(valorC >= 50 && valorC <= 1000000)) return erro('Valor inválido (mínimo €0,50).');
        const descricao = String(corpo.descricao || 'Serviço de transporte').slice(0, 120);
        const lang = corpo.idioma === 'en' ? 'en' : 'pt';
        const params = {
          mode: 'payment',
          'line_items[0][quantity]': 1,
          'line_items[0][price_data][currency]': 'eur',
          'line_items[0][price_data][unit_amount]': valorC,
          'line_items[0][price_data][product_data][name]': descricao,
          success_url: url.origin + '/obrigado?l=' + lang,
          locale: 'auto',
          metadata: { trajeto_uid: u.uid, servico: String(corpo.servicoId || '').slice(0, 60) },
          payment_intent_data: { description: descricao, metadata: { trajeto_uid: u.uid, servico: String(corpo.servicoId || '').slice(0, 60) } }
        };
        let conta = '', taxaC = 0;
        if(!dono){
          const a = await contaDoMotorista(env, u, corpo.conta);
          if(!a || !a.charges_enabled) return erro('Ativa primeiro os pagamentos online (Minhas tarifas → 💳 Pagamentos online).', 403);
          conta = a.id;
          const sub = await assinaturaPro(env, u).catch(() => null);
          taxaC = sub ? 0 : taxaAppCent(valorC, taxaCfg(env));
          if(taxaC > 0) params.payment_intent_data.application_fee_amount = taxaC;
        }
        const s = await stripe(env, 'POST', '/checkout/sessions', params, conta || undefined);
        return json({ id: s.id, url: s.url, conta, taxaC });
      }

      // ---- estado da cobrança ----
      if(caminho === '/estado'){
        const id = url.searchParams.get('id') || '';
        if(!/^cs_[A-Za-z0-9_]+$/.test(id)) return erro('Cobrança inválida.');
        let conta = '';
        if(!dono){ const a = await contaDoMotorista(env, u, url.searchParams.get('conta')); if(!a) return erro('Conta inválida.', 403); conta = a.id; }
        const s = await stripe(env, 'GET', '/checkout/sessions/' + id, null, conta || undefined);
        if(!s.metadata || s.metadata.trajeto_uid !== u.uid) return erro('Esta cobrança não é tua.', 403);
        return json({ pago: s.payment_status === 'paid', estado: s.status === 'expired' ? 'expirada' : s.payment_status === 'paid' ? 'paga' : 'aberta' });
      }

      // ---- fase 2: ativar pagamentos do motorista ----
      if(caminho === '/connect/ativar' && req.method === 'POST'){
        if(dono) return erro('A tua conta já é a conta principal: não precisas de ativar.');
        let a = await contaDoMotorista(env, u, corpo.conta);
        if(!a){
          a = await stripe(env, 'POST', '/accounts', {
            type: 'express', country: 'PT', email: u.email || undefined, business_type: 'individual',
            capabilities: { card_payments: { requested: true }, transfers: { requested: true } },
            business_profile: { mcc: '4121', product_description: 'Transporte privado de passageiros (transfers e tours)' },
            metadata: { trajeto_uid: u.uid }
          });
          if(env.CONTAS) await env.CONTAS.put(u.uid, a.id);
        }
        const link = await stripe(env, 'POST', '/account_links', {
          account: a.id, type: 'account_onboarding',
          refresh_url: voltarUrl(env, corpo.voltar, 'refresh'), return_url: voltarUrl(env, corpo.voltar, 'volta')
        });
        return json({ url: link.url, conta: a.id });
      }
      if(caminho === '/connect/painel' && req.method === 'POST'){
        const a = await contaDoMotorista(env, u, corpo.conta);
        if(!a) return erro('Ainda não ativaste os pagamentos.', 404);
        const l = await stripe(env, 'POST', '/accounts/' + a.id + '/login_links', {});
        return json({ url: l.url });
      }

      // ---- fase 2: plano PRO (mensalidade, sem taxa da app) ----
      if(caminho === '/pro/assinar' && req.method === 'POST'){
        if(!env.PRO_PRICE_ID) return erro('O plano PRO ainda não está disponível.', 404);
        const s = await stripe(env, 'POST', '/checkout/sessions', {
          mode: 'subscription', 'line_items[0][price]': env.PRO_PRICE_ID, 'line_items[0][quantity]': 1,
          customer_email: u.email || undefined, locale: 'pt',
          subscription_data: { metadata: { trajeto_uid: u.uid } }, metadata: { trajeto_uid: u.uid },
          success_url: voltarUrl(env, corpo.voltar, 'pro'), cancel_url: voltarUrl(env, corpo.voltar, 'volta')
        });
        return json({ url: s.url });
      }
      if(caminho === '/pro/gerir' && req.method === 'POST'){
        const sub = await assinaturaPro(env, u);
        if(!sub) return erro('Não tens o plano PRO ativo.', 404);
        const p = await stripe(env, 'POST', '/billing_portal/sessions', { customer: sub.customer, return_url: voltarUrl(env, corpo.voltar, 'volta') });
        return json({ url: p.url });
      }

      return erro('Pedido desconhecido.', 404);
    }catch(e){
      return erro(e.stripe ? 'Stripe: ' + e.message : 'Erro no serviço de pagamentos.', 502);
    }
  }
};
