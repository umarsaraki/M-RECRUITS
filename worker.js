const enc=new TextEncoder();
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const SEC={'x-content-type-options':'nosniff','referrer-policy':'strict-origin-when-cross-origin','x-frame-options':'DENY','content-security-policy':"frame-ancestors 'none'"};
const json=(d,s=200,h={})=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json',...SEC,...h}});
const fail=(m,s=400)=>json({error:m},s);
const MAXB=6*1024*1024,CV_MAX=5*1024*1024;
const s=(v,max=500)=>String(v??'').trim().slice(0,max);
const emailOk=e=>/^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(e)&&e.length<=254;
const ref=p=>p+'-'+rnd(4).toUpperCase();
const ip=r=>r.headers.get('cf-connecting-ip')||'0';

async function limit(env,key,max,sec){const w=Math.floor(Date.now()/1000/sec);
 const r=await env.DB.prepare('INSERT INTO rate_limits(k,w,c) VALUES(?,?,1) ON CONFLICT(k,w) DO UPDATE SET c=c+1 RETURNING c').bind(key,w).first();return r.c<=max}
async function hashPw(pw,salt=rnd(16)){const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);
 const b=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:100000},k,256);return salt+':'+hex(b)}
async function checkPw(pw,stored){const [salt]=stored.split(':');const h=await hashPw(pw,salt);return h.length===stored.length&&h===stored}
async function audit(env,req,admin,action,entity,id){await env.DB.prepare('INSERT INTO audit_logs(admin_id,action,entity,entity_id,ip_hash) VALUES(?,?,?,?,?)').bind(admin?.uid??null,action,entity??null,id?String(id):null,(await sha(ip(req))).slice(0,16)).run()}
async function hmac(env,msg){const k=await crypto.subtle.importKey('raw',enc.encode(env.SESSION_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);return hex(await crypto.subtle.sign('HMAC',k,enc.encode(msg)))}

async function adminAuth(req,env){
 const m=(req.headers.get('cookie')||'').match(/mr_s=([a-f0-9]{64})/);if(!m)return null;
 const row=await env.DB.prepare('SELECT s.user_id uid,s.csrf,u.role,u.email FROM admin_sessions s JOIN admin_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(await sha(m[1]),Date.now()).first();
 if(!row)return null;
 if(!['GET','HEAD'].includes(req.method)&&req.headers.get('x-csrf-token')!==row.csrf)return 'csrf';
 return row}

function corsHeaders(req,env){const o=req.headers.get('origin');return o&&o===env.ALLOWED_ORIGIN?{'access-control-allow-origin':o,'access-control-allow-credentials':'true','access-control-allow-headers':'content-type,x-csrf-token','access-control-allow-methods':'GET,POST,PATCH,DELETE','vary':'origin'}:{}}

async function body(req){const t=await req.text();if(t.length>100000)throw new Error('big');return JSON.parse(t||'{}')}

// ---------- public ----------
async function listJobs(url,env){
 const q=url.searchParams,w=["status='published'","(deadline IS NULL OR deadline>=date('now'))"],p=[],lk=v=>`%${v.replace(/[%_]/g,'')}%`;
 const kw=s(q.get('q'),80),co=s(q.get('company'),80),loc=s(q.get('location'),80),cat=parseInt(q.get('category')),typ=s(q.get('type'),30),mode=s(q.get('mode'),20),sal=s(q.get('salary'),20),cur=(s(q.get('currency'),5).toUpperCase()||'NGN'),country=s(q.get('country'),60),state=s(q.get('state'),60),city=s(q.get('city'),60);
 if(kw){w.push('(title LIKE ? OR description LIKE ? OR skills LIKE ?)');p.push(lk(kw),lk(kw),lk(kw))}
 if(co){w.push('company LIKE ?');p.push(lk(co))}
 if(loc){w.push('(location LIKE ? OR city LIKE ? OR state LIKE ? OR country LIKE ?)');p.push(lk(loc),lk(loc),lk(loc),lk(loc))}
 if(cat>0){w.push('category_id=?');p.push(cat)}
 if(typ){w.push('employment_type=?');p.push(typ)}
 if(country==='remote')w.push("work_mode='Remote'");else if(country){w.push('country=?');p.push(country)}
 if(state){w.push('state=?');p.push(state)}if(city){w.push('city=?');p.push(city)}
 if(['Remote','Hybrid','On-site'].includes(mode)){w.push('work_mode=?');p.push(mode)}
 const B={lt100k:[0,100000],'100-300k':[100000,300000],'300-500k':[300000,500000],'500k-1m':[500000,1000000],gt1m:[1000000,null]};
 if(sal==='negotiable')w.push("salary_type='negotiable'");
 else if(sal==='undisclosed')w.push("(salary_type='undisclosed' OR (salary_type='range' AND salary_min IS NULL AND salary_max IS NULL))");
 else if(B[sal]){const[a,b]=B[sal];w.push("salary_type='range' AND currency=? AND COALESCE(salary_max,salary_min)>=?");p.push(cur,a);if(b!=null){w.push('COALESCE(salary_max,salary_min)<?');p.push(b)}}
 const sort=s(q.get('sort'),12),SV='COALESCE(salary_max,salary_min,0)';let order='created_at DESC',op=[];
 if(sort==='oldest')order='created_at ASC';else if(sort==='high')order=`${SV} DESC,created_at DESC`;else if(sort==='low')order=`(CASE WHEN ${SV}=0 THEN 1 ELSE 0 END),${SV} ASC`;
 else if(sort==='relevant'&&kw){order='(CASE WHEN title LIKE ? THEN 0 WHEN company LIKE ? THEN 1 ELSE 2 END),created_at DESC';op=[lk(kw),lk(kw)]}
 else if(!sort&&q.get('featured')!=='1')order='featured DESC,created_at DESC';
 if(q.get('featured')==='1')w.push('featured=1');
 const page=Math.max(1,parseInt(q.get('page'))||1),size=Math.min(30,parseInt(q.get('size'))||10),W=w.join(' AND ');
 const [rows,tot]=await Promise.all([
  env.DB.prepare(`SELECT id,title,company,logo_key,location,country,state,city,work_mode,category_id,employment_type,salary_type,salary_min,salary_max,currency,deadline,featured,created_at FROM jobs WHERE ${W} ORDER BY ${order} LIMIT ? OFFSET ?`).bind(...p,...op,size,(page-1)*size).all(),
  env.DB.prepare(`SELECT COUNT(*) n FROM jobs WHERE ${W}`).bind(...p).first()]);
 return {jobs:rows.results,page,size,total:tot.n}}

async function submitApplication(req,env){
 if(!(await limit(env,'app:'+ip(req),5,3600)))return fail('Too many submissions. Try later.',429);
 if(+req.headers.get('content-length')>MAXB)return fail('Request too large',413);
 const f=await req.formData(),g=k=>s(f.get(k),k==='cover_letter'||k==='experience'?4000:300);
 const job_id=parseInt(g('job_id')),d={full_name:g('full_name'),email:g('email').toLowerCase(),phone:g('phone'),location:g('location'),education:g('education'),experience:g('experience'),skills:g('skills'),cover_letter:g('cover_letter')};
 const errs={};
 if(d.full_name.length<2)errs.full_name='Required';if(!emailOk(d.email))errs.email='Invalid email';
 if(!/^\+?[0-9 ()-]{7,20}$/.test(d.phone))errs.phone='Invalid phone';
 for(const k of['location','education','experience','skills'])if(!d[k])errs[k]='Required';
 if(f.get('consent')!=='true')errs.consent='Consent is required';
 const cv=f.get('cv');if(!(cv instanceof File)||!cv.size)errs.cv='CV required';
 const types={pdf:['application/pdf'],doc:['application/msword'],docx:['application/vnd.openxmlformats-officedocument.wordprocessingml.document']};
 let ext='';
 if(cv instanceof File&&cv.size){ext=(cv.name.split('.').pop()||'').toLowerCase();
  if(!types[ext]?.includes(cv.type))errs.cv='Only PDF, DOC or DOCX';else if(cv.size>CV_MAX)errs.cv='Max 5MB';
  else{const h=new Uint8Array(await cv.slice(0,4).arrayBuffer());const sig=hex(h);
   if((ext==='pdf'&&sig!=='25504446')||(ext==='docx'&&sig!=='504b0304')||(ext==='doc'&&sig!=='d0cf11e0'))errs.cv='File content does not match type'}}
 if(Object.keys(errs).length)return json({error:'Validation failed',fields:errs},422);
 const job=await env.DB.prepare("SELECT id FROM jobs WHERE id=? AND status='published' AND (deadline IS NULL OR deadline>=date('now'))").bind(job_id).first();
 if(!job)return fail('Vacancy not available',404);
 if(await env.DB.prepare('SELECT 1 FROM applications WHERE job_id=? AND email=?').bind(job_id,d.email).first())return fail('You have already applied for this vacancy',409);
 const reference=ref('MR'),key=`private/cv/${reference}-${rnd(8)}.${ext}`;
 await env.MEDIA_BUCKET.put(key,cv.stream(),{httpMetadata:{contentType:cv.type}});
 try{await env.DB.prepare('INSERT INTO applications(reference,job_id,full_name,email,phone,location,education,experience,skills,cover_letter,cv_key,cv_name,cv_size,consent) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)').bind(reference,job_id,d.full_name,d.email,d.phone,d.location,d.education,d.experience,d.skills,d.cover_letter,key,cv.name.slice(0,120),cv.size).run()}
 catch(e){await env.MEDIA_BUCKET.delete(key);return fail('Could not save application (possible duplicate)',409)}
 return json({reference},201)}

async function simpleInsert(req,env,table,fields,prefix,extra){
 if(!(await limit(env,table+':'+ip(req),8,3600)))return fail('Too many requests',429);
 let b;try{b=await body(req)}catch{return fail('Invalid JSON')}
 const v={};for(const[k,t,max]of fields){v[k]=t==='int'?parseInt(b[k]):s(b[k],max||300);
  if(t==='req'&&!v[k]||t==='int'&&!(v[k]>0)||t==='email'&&!emailOk(v[k]))return fail('Invalid or missing: '+k,422)}
 if(b.consent!==true&&table==='employer_inquiries'&&false)return fail('Consent required',422);
 const reference=ref(prefix),cols=Object.keys(v),extraV=extra?await extra(v,env):{};
 if(extraV===null)return fail('Unknown service',404);
 const all={...v,...extraV};
 await env.DB.prepare(`INSERT INTO ${table}(reference,${Object.keys(all).join(',')}) VALUES(?,${Object.keys(all).map(()=>'?').join(',')})`).bind(reference,...Object.values(all)).run();
 return json({reference},201)}

// ---------- router ----------
// ======================================================================
//  AUTOMATIC DATABASE SETUP  (Cloudflare D1, binding name: DB)
//  No SQL file is needed. On the first request the Worker creates every
//  table below (CREATE TABLE IF NOT EXISTS), adds any missing column, then
//  adds indexes and starter content (categories, services).
//
//  TO CHANGE THE DATABASE LATER:
//   - new table   -> add a CREATE TABLE IF NOT EXISTS statement to TABLES
//   - new column  -> add [table, column, definition] to COLS
//   - new index / starter rows -> add to AFTER
//   then increase SCHEMA_VERSION by 1 and deploy. It applies by itself.
// ======================================================================
const SCHEMA_VERSION=3;

// ---------------------------- TABLES ----------------------------------
const TABLES=[
  `CREATE TABLE IF NOT EXISTS admin_users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'superadmin' CHECK(role IN('superadmin','admin','recruiter')),
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS admin_sessions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS job_categories(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,
    icon TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0
  )`,

  `CREATE TABLE IF NOT EXISTS jobs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    company TEXT NOT NULL,
    company_info TEXT,
    logo_key TEXT,
    location TEXT NOT NULL,
    category_id INTEGER REFERENCES job_categories(id) ON DELETE SET NULL,
    employment_type TEXT NOT NULL,
    salary_min INTEGER,
    salary_max INTEGER,
    currency TEXT DEFAULT 'NGN',
    salary_type TEXT NOT NULL DEFAULT 'range',
    work_mode TEXT,
    country TEXT,
    state TEXT,
    city TEXT,
    skills TEXT,
    experience_level TEXT,
    benefits TEXT,
    description TEXT NOT NULL,
    responsibilities TEXT,
    requirements TEXT,
    vacancies INTEGER NOT NULL DEFAULT 1 CHECK(vacancies>=0),
    deadline TEXT,
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN('draft','published','filled','expired')),
    featured INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS applications(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT NOT NULL UNIQUE,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    location TEXT NOT NULL,
    education TEXT NOT NULL,
    experience TEXT NOT NULL,
    skills TEXT NOT NULL,
    cover_letter TEXT,
    cv_key TEXT NOT NULL,
    cv_name TEXT,
    cv_size INTEGER,
    consent INTEGER NOT NULL CHECK(consent=1),
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN('Pending','Under Review','Shortlisted','Interview Scheduled','Accepted','Rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(job_id,email)
  )`,

  `CREATE TABLE IF NOT EXISTS application_notes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    admin_id INTEGER REFERENCES admin_users(id),
    note TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS interview_records(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    scheduled_at TEXT NOT NULL,
    mode TEXT,
    location_or_link TEXT,
    result TEXT CHECK(result IN('Pending','Passed','Failed','No Show')) DEFAULT 'Pending',
    feedback TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS employer_inquiries(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT NOT NULL UNIQUE,
    company TEXT NOT NULL,
    contact_person TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    location TEXT NOT NULL,
    industry TEXT NOT NULL,
    staff_required INTEGER NOT NULL CHECK(staff_required>0),
    positions TEXT NOT NULL,
    employment_type TEXT NOT NULL,
    requirements TEXT NOT NULL,
    additional_info TEXT,
    status TEXT NOT NULL DEFAULT 'New' CHECK(status IN('New','Contacted','In Progress','Closed','Archived')),
    admin_notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS services(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    audience TEXT,
    full_description TEXT,
    benefits TEXT NOT NULL DEFAULT '[]',
    how_it_works TEXT NOT NULL DEFAULT '[]',
    image_key TEXT,
    icon TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0
  )`,

  `CREATE TABLE IF NOT EXISTS service_requests(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT NOT NULL UNIQUE,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    message TEXT,
    company TEXT,
    location TEXT,
    archived INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'New' CHECK(status IN('New','In Progress','Completed','Cancelled')),
    admin_notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS contact_messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    subject TEXT,
    message TEXT NOT NULL,
    handled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS homepage_banners(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_key TEXT NOT NULL,
    headline TEXT,
    subtitle TEXT,
    link TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1
  )`,

  `CREATE TABLE IF NOT EXISTS website_settings(
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS encrypted_integrations(
    provider TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    masked TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS media_assets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    r2_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    uploaded_by INTEGER REFERENCES admin_users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS saved_job_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS audit_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action TEXT NOT NULL,
    entity TEXT,
    entity_id TEXT,
    ip_hash TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS rate_limits(
    k TEXT NOT NULL,
    w INTEGER NOT NULL,
    c INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(k,w)
  )`
];

// ------------- COLUMNS added after first release (safe to re-run) -----
const COLS=[
  ["jobs", "salary_type", "TEXT NOT NULL DEFAULT 'range'"],
  ["jobs", "work_mode", "TEXT"],
  ["jobs", "country", "TEXT"],
  ["jobs", "state", "TEXT"],
  ["jobs", "city", "TEXT"],
  ["jobs", "skills", "TEXT"],
  ["jobs", "experience_level", "TEXT"],
  ["jobs", "benefits", "TEXT"],
  ["services", "audience", "TEXT"],
  ["services", "full_description", "TEXT"],
  ["services", "how_it_works", "TEXT NOT NULL DEFAULT '[]'"],
  ["services", "image_key", "TEXT"],
  ["service_requests", "company", "TEXT"],
  ["service_requests", "location", "TEXT"],
  ["service_requests", "archived", "INTEGER NOT NULL DEFAULT 0"]
];

// ------------- INDEXES + STARTER CONTENT (safe to re-run) -------------
const AFTER=[
  `CREATE INDEX IF NOT EXISTS idx_jobs_pub ON jobs(status,created_at DESC)`,

  `CREATE INDEX IF NOT EXISTS idx_jobs_loc ON jobs(status,country,state,city)`,

  `CREATE INDEX IF NOT EXISTS idx_jobs_company ON jobs(company)`,

  `CREATE INDEX IF NOT EXISTS idx_jobs_filter ON jobs(status,category_id,location,employment_type)`,

  `CREATE INDEX IF NOT EXISTS idx_app_status ON applications(status,created_at DESC)`,

  `CREATE INDEX IF NOT EXISTS idx_app_email ON applications(email)`,

  `CREATE INDEX IF NOT EXISTS idx_inq_status ON employer_inquiries(status,created_at DESC)`,

  `CREATE INDEX IF NOT EXISTS idx_audit ON audit_logs(created_at DESC)`,

  `INSERT OR IGNORE INTO services(slug,name,description,audience,full_description,benefits,how_it_works,icon,sort_order) VALUES
('recruitment-staffing','Recruitment & Staffing','Connecting employers with reliable, qualified and experienced candidates.','Employers and organizations','We help organizations find, screen and hire the right people. From a single vacancy to large-scale staffing, we manage sourcing, shortlisting and coordination so you can focus on your business.','["Access to qualified, screened candidates", "Faster time to hire", "Reduced recruitment workload", "Flexible staffing options"]','["Tell us the roles and requirements you need to fill", "We source and screen suitable candidates", "You receive a shortlist to review and interview", "We support the hiring decision and placement"]','recruitment',1),
('cv-writing','CV Writing & Revamping','Professional CV creation and improvement to help candidates present their qualifications effectively.','Job seekers','We create and improve CVs that present your qualifications, experience and achievements clearly and professionally.','["Professional, well-structured layout", "Clearer presentation of your strengths", "Tailored to your target roles", "Improved chances of being shortlisted"]','["Send us your current CV or career details", "We review your goals and target roles", "We write or revamp your CV", "You review it and request adjustments"]','cv',2),
('staff-training','Staff Training & Development','Professional development and training solutions to improve employee skills and workplace performance.','Employers and organizations','We design and deliver training programmes that build skills, strengthen teams and improve performance in the workplace.','["Improved employee skills", "Better workplace performance", "Programmes suited to your needs", "Higher staff confidence and retention"]','["Share your training needs and team size", "We recommend a suitable programme", "Training is delivered to your team", "We follow up on results with you"]','training',3),
('career-guidance','Career Guidance & Coaching','Career advice, professional development guidance and job search support.','Job seekers and graduates','One-to-one guidance to help you plan your career, make informed decisions and approach your job search with confidence.','["Clear direction for your career", "Guidance on job search strategy", "Support for graduates entering work", "Confidence in your next step"]','["Tell us about your background and goals", "We discuss your options and agree a plan", "We guide your job search and development", "We follow up as you progress"]','career',4),
('interview-onboarding','Interview & Onboarding Support','Interview preparation and structured onboarding assistance for employers and candidates.','Employers and candidates','We prepare candidates for interviews and help employers set up structured onboarding so new hires settle in and succeed.','["Stronger interview performance", "Structured onboarding for new hires", "Smoother transition from hire to success", "Better early retention"]','["Tell us whether you are a candidate or an employer", "We prepare the interview or onboarding plan", "We support you through the process", "We review progress together"]','interview',5)`,

  `INSERT OR IGNORE INTO job_categories(name,slug,sort_order) VALUES
('Information Technology','information-technology',1),
('Administration','administration',2),
('Accounting & Finance','accounting-finance',3),
('Engineering','engineering',4),
('Healthcare','healthcare',5),
('Education','education',6),
('Sales & Marketing','sales-marketing',7),
('Customer Service','customer-service',8),
('Hospitality & Tourism','hospitality-tourism',9),
('Logistics & Transportation','logistics-transportation',10),
('Construction','construction',11),
('Human Resources','human-resources',12),
('Remote Jobs','remote-jobs',13),
('Other Jobs','other-jobs',14)`,

  `CREATE INDEX IF NOT EXISTS idx_sr_status ON service_requests(archived,status,created_at DESC)`,

  `UPDATE services SET audience='Employers and organizations',full_description='We help organizations find, screen and hire the right people. From a single vacancy to large-scale staffing, we manage sourcing, shortlisting and coordination so you can focus on your business.',benefits='["Access to qualified, screened candidates", "Faster time to hire", "Reduced recruitment workload", "Flexible staffing options"]',how_it_works='["Tell us the roles and requirements you need to fill", "We source and screen suitable candidates", "You receive a shortlist to review and interview", "We support the hiring decision and placement"]' WHERE slug='recruitment-staffing' AND audience IS NULL`,

  `UPDATE services SET audience='Job seekers',full_description='We create and improve CVs that present your qualifications, experience and achievements clearly and professionally.',benefits='["Professional, well-structured layout", "Clearer presentation of your strengths", "Tailored to your target roles", "Improved chances of being shortlisted"]',how_it_works='["Send us your current CV or career details", "We review your goals and target roles", "We write or revamp your CV", "You review it and request adjustments"]' WHERE slug='cv-writing' AND audience IS NULL`,

  `UPDATE services SET audience='Employers and organizations',full_description='We design and deliver training programmes that build skills, strengthen teams and improve performance in the workplace.',benefits='["Improved employee skills", "Better workplace performance", "Programmes suited to your needs", "Higher staff confidence and retention"]',how_it_works='["Share your training needs and team size", "We recommend a suitable programme", "Training is delivered to your team", "We follow up on results with you"]' WHERE slug='staff-training' AND audience IS NULL`,

  `UPDATE services SET audience='Job seekers and graduates',full_description='One-to-one guidance to help you plan your career, make informed decisions and approach your job search with confidence.',benefits='["Clear direction for your career", "Guidance on job search strategy", "Support for graduates entering work", "Confidence in your next step"]',how_it_works='["Tell us about your background and goals", "We discuss your options and agree a plan", "We guide your job search and development", "We follow up as you progress"]' WHERE slug='career-guidance' AND audience IS NULL`,

  `UPDATE services SET audience='Employers and candidates',full_description='We prepare candidates for interviews and help employers set up structured onboarding so new hires settle in and succeed.',benefits='["Stronger interview performance", "Structured onboarding for new hires", "Smoother transition from hire to success", "Better early retention"]',how_it_works='["Tell us whether you are a candidate or an employer", "We prepare the interview or onboarding plan", "We support you through the process", "We review progress together"]' WHERE slug='interview-onboarding' AND audience IS NULL`
];

let ready;
function ensureDb(env){return ready||(ready=(async()=>{
 let v=0;try{v=(await env.DB.prepare('SELECT MAX(version) v FROM schema_migrations').first())?.v||0}catch{}
 if(v>=SCHEMA_VERSION)return;
 await env.DB.prepare('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();
 await env.DB.batch(TABLES.map(x=>env.DB.prepare(x)));
 for(const[t,c,d]of COLS){const have=(await env.DB.prepare(`PRAGMA table_info(${t})`).all()).results;
  if(!have.some(x=>x.name===c)){try{await env.DB.prepare(`ALTER TABLE ${t} ADD COLUMN ${c} ${d}`).run()}catch(e){if(!/duplicate column/i.test(e.message))throw e}}}
 await env.DB.batch(AFTER.map(x=>env.DB.prepare(x)));
 await env.DB.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES(?)').bind(SCHEMA_VERSION).run();
})().catch(e=>{ready=null;throw e}))}

export default{async fetch(req,env){
 const url=new URL(req.url),path=url.pathname,cors=corsHeaders(req,env);
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors});
 if(!path.startsWith('/api/')&&!path.startsWith('/media/'))return env.ASSETS.fetch(req);
 try{await ensureDb(env);const r=await route(req,env,url,path);const h=new Headers(r.headers);for(const[k,v]of Object.entries(cors))h.set(k,v);return new Response(r.body,{status:r.status,headers:h})}
 catch(e){console.error('err',path,e.message);return fail('Internal error',500)}},

 async scheduled(){}};

async function route(req,env,url,path){
 const M=req.method,seg=path.split('/').filter(Boolean);
 const cache={'cache-control':'public, max-age=60, s-maxage=120'};
 // public media only
 if(seg[0]==='media'){const key=seg.slice(1).join('/');if(!key.startsWith('public/'))return fail('Not found',404);
  const o=await env.MEDIA_BUCKET.get(key);if(!o)return fail('Not found',404);
  return new Response(o.body,{headers:{'content-type':o.httpMetadata?.contentType||'application/octet-stream','cache-control':'public, max-age=86400',...SEC}})}
 if(seg[1]==='admin')return admin(req,env,url,seg,M);
 if(M==='GET'&&path==='/api/jobs')return json(await listJobs(url,env),200,cache);
 if(M==='GET'&&seg[1]==='jobs'&&seg[2]){const id=parseInt(seg[2]);
  const j=await env.DB.prepare("SELECT * FROM jobs WHERE id=? AND status='published'").bind(id).first();if(!j)return fail('Not found',404);
  const rel=await env.DB.prepare("SELECT id,title,company,location,employment_type FROM jobs WHERE status='published' AND id!=? AND category_id IS ? ORDER BY created_at DESC LIMIT 4").bind(id,j.category_id).all();
  return json({job:j,related:rel.results},200,cache)}
 if(M==='GET'&&path==='/api/jobs-by-ids'){const ids=(url.searchParams.get('ids')||'').split(',').map(Number).filter(n=>Number.isInteger(n)&&n>0).slice(0,50);if(!ids.length)return json({jobs:[]});
  const r=await env.DB.prepare(`SELECT id,title,company,logo_key,location,employment_type,salary_type,salary_min,salary_max,currency,work_mode,deadline,created_at FROM jobs WHERE status='published' AND id IN (${ids.map(()=>'?').join(',')})`).bind(...ids).all();return json({jobs:r.results})}
 if(M==='GET'&&path==='/api/job-filters'){const g=async c=>(await env.DB.prepare(`SELECT DISTINCT ${c} v FROM jobs WHERE status='published' AND ${c} IS NOT NULL AND ${c}!='' ORDER BY v LIMIT 100`).all()).results.map(r=>r.v);return json({countries:await g('country'),states:await g('state'),cities:await g('city')},200,cache)}
 if(M==='GET'&&path==='/api/categories')return json((await env.DB.prepare('SELECT c.id,c.name,c.slug,c.icon,(SELECT COUNT(*) FROM jobs j WHERE j.category_id=c.id AND j.status=\'published\') open_jobs FROM job_categories c ORDER BY sort_order,name').all()).results,200,cache);
 if(M==='GET'&&path==='/api/services')return json((await env.DB.prepare('SELECT id,slug,name,description,full_description,audience,benefits,how_it_works,image_key,icon FROM services WHERE active=1 ORDER BY sort_order').all()).results,200,cache);
 if(M==='GET'&&path==='/api/banners')return json((await env.DB.prepare("SELECT id,image_key,headline,subtitle,link FROM homepage_banners WHERE active=1 AND (starts_at IS NULL OR starts_at<=CURRENT_TIMESTAMP) AND (ends_at IS NULL OR ends_at>=CURRENT_TIMESTAMP) ORDER BY sort_order,id").all()).results,200,cache);
 if(M==='GET'&&path==='/api/stats'){const r=await env.DB.prepare("SELECT (SELECT COUNT(*) FROM jobs WHERE status='published') jobs,(SELECT COUNT(*) FROM applications) applications,(SELECT COUNT(*) FROM employer_inquiries) employers").first();return json(r,200,cache)}
 if(M==='GET'&&path==='/api/settings'){const r=await env.DB.prepare("SELECT key,value FROM website_settings WHERE key NOT LIKE 'private_%'").all();return json(Object.fromEntries(r.results.map(x=>[x.key,x.value])),200,cache)}
 if(M==='POST'&&path==='/api/applications')return submitApplication(req,env);
 if(M==='POST'&&path==='/api/applications/track'){
  if(!(await limit(env,'trk:'+ip(req),30,600)))return fail('Too many attempts',429);
  let b;try{b=await body(req)}catch{return fail('Invalid JSON')}
  const r=await env.DB.prepare('SELECT a.id,a.reference,a.status,a.created_at,a.education,a.experience,a.skills,a.cover_letter,a.cv_name,a.cv_size,j.id job_id,j.title,j.company,j.company_info,j.logo_key,j.location,j.employment_type,j.salary_type,j.salary_min,j.salary_max,j.currency,j.description,j.responsibilities,j.requirements,j.deadline FROM applications a JOIN jobs j ON j.id=a.job_id WHERE a.reference=? AND a.email=?').bind(s(b.reference,30).toUpperCase(),s(b.email,254).toLowerCase()).first();
  if(!r)return fail('No application matches that reference and email',404);
  const iv=await env.DB.prepare('SELECT scheduled_at,mode,location_or_link FROM interview_records WHERE application_id=? ORDER BY scheduled_at DESC LIMIT 1').bind(r.id).first();
  const {id,...pub}=r;return json({...pub,interview:iv||null},200,{'cache-control':'no-store'})}
 if(M==='POST'&&path==='/api/applications/track-many'){
  if(!(await limit(env,'trkm:'+ip(req),30,600)))return fail('Too many attempts',429);
  let b;try{b=await body(req)}catch{return fail('Invalid JSON')}
  const it=(Array.isArray(b.items)?b.items:[]).slice(0,20).filter(x=>x&&typeof x.reference==='string'&&typeof x.email==='string');
  if(!it.length)return json({applications:[]});
  const sql='SELECT a.reference,a.status,a.created_at,j.id job_id,j.title,j.company,j.logo_key,j.location,j.employment_type,j.salary_type,j.salary_min,j.salary_max,j.currency FROM applications a JOIN jobs j ON j.id=a.job_id WHERE a.reference=? AND a.email=?';
  const rs=await env.DB.batch(it.map(x=>env.DB.prepare(sql).bind(s(x.reference,30).toUpperCase(),s(x.email,254).toLowerCase())));
  return json({applications:rs.flatMap(r=>r.results)},200,{'cache-control':'no-store'})}
 if(M==='POST'&&path==='/api/employer-inquiries')return simpleInsert(req,env,'employer_inquiries',[['company','req'],['contact_person','req'],['email','email'],['phone','req',30],['location','req'],['industry','req'],['staff_required','int'],['positions','req',1000],['employment_type','req',50],['requirements','req',3000],['additional_info','',3000]],'EI');
 if(M==='POST'&&path==='/api/service-requests')return simpleInsert(req,env,'service_requests',[['full_name','req'],['email','email'],['phone','req',30],['message','',2000],['company','',200],['location','req',200],['service_id','int']],'SR',async(v,e)=>{const x=await e.DB.prepare('SELECT id FROM services WHERE id=? AND active=1').bind(v.service_id).first();return x?{}:null});
 if(M==='POST'&&path==='/api/contact')return(async()=>{if(!(await limit(env,'ct:'+ip(req),5,3600)))return fail('Too many requests',429);let b;try{b=await body(req)}catch{return fail('Invalid JSON')}
  if(!s(b.name)||!emailOk(s(b.email))||!s(b.message))return fail('Name, valid email and message required',422);
  await env.DB.prepare('INSERT INTO contact_messages(name,email,subject,message) VALUES(?,?,?,?)').bind(s(b.name),s(b.email),s(b.subject),s(b.message,3000)).run();return json({ok:true},201)})();
 return fail('Not found',404)}

// ---------- admin ----------
async function admin(req,env,url,seg,M){
 const a=seg[2];
 if(a==='bootstrap'&&M==='POST'){ // one-time: create first admin
  if(!(await limit(env,'boot:'+ip(req),3,3600)))return fail('Too many attempts',429);
  if((await env.DB.prepare('SELECT COUNT(*) n FROM admin_users').first()).n>0)return fail('Already initialised',403);
  let b;try{b=await body(req)}catch{return fail('Invalid JSON')}
  if(!env.ADMIN_BOOTSTRAP_SECRET||b.secret!==env.ADMIN_BOOTSTRAP_SECRET)return fail('Forbidden',403);
  if(!emailOk(s(b.email))||s(b.password,200).length<12)return fail('Valid email and password of 12+ characters required',422);
  await env.DB.prepare('INSERT INTO admin_users(email,password_hash) VALUES(?,?)').bind(s(b.email).toLowerCase(),await hashPw(b.password)).run();
  await audit(env,req,null,'bootstrap','admin_users');return json({ok:true},201)}
 if(a==='login'&&M==='POST'){
  if(!(await limit(env,'login:'+ip(req),10,900)))return fail('Too many attempts',429);
  let b;try{b=await body(req)}catch{return fail('Invalid JSON')}
  const u=await env.DB.prepare('SELECT * FROM admin_users WHERE email=?').bind(s(b.email,254).toLowerCase()).first();
  if(u?.locked_until>Date.now())return fail('Account temporarily locked',423);
  if(!u||!(await checkPw(String(b.password||''),u.password_hash))){
   if(u)await env.DB.prepare('UPDATE admin_users SET failed_logins=failed_logins+1,locked_until=CASE WHEN failed_logins+1>=5 THEN ? ELSE NULL END WHERE id=?').bind(Date.now()+900000,u.id).run();
   return fail('Invalid credentials',401)}
  await env.DB.prepare('UPDATE admin_users SET failed_logins=0,locked_until=NULL WHERE id=?').bind(u.id).run();
  const tok=rnd(32),csrf=rnd(16);
  await env.DB.prepare('INSERT INTO admin_sessions(user_id,token_hash,csrf,expires_at) VALUES(?,?,?,?)').bind(u.id,await sha(tok),csrf,Date.now()+8*3600e3).run();
  await audit(env,req,{uid:u.id},'login');
  return json({csrf,email:u.email},200,{'set-cookie':`mr_s=${tok}; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=28800`})}
 const au=await adminAuth(req,env);
 if(au==='csrf')return fail('CSRF check failed',403);
 if(!au)return fail('Unauthorized',401);
 const id=parseInt(seg[3]);
 if(a==='logout'&&M==='POST'){const m=req.headers.get('cookie').match(/mr_s=([a-f0-9]{64})/);await env.DB.prepare('DELETE FROM admin_sessions WHERE token_hash=?').bind(await sha(m[1])).run();return json({ok:true},200,{'set-cookie':'mr_s=; Max-Age=0; Path=/api/admin; HttpOnly; Secure'})}
 if(a==='me')return json({email:au.email,role:au.role,csrf:au.csrf});
 if(a==='overview'){const r=await env.DB.prepare("SELECT (SELECT COUNT(*) FROM applications) applications,(SELECT COUNT(*) FROM jobs WHERE status='published') published,(SELECT COUNT(*) FROM jobs WHERE status='draft') drafts,(SELECT COUNT(*) FROM service_requests) service_requests,(SELECT COUNT(*) FROM employer_inquiries) inquiries").first();
  const by=await env.DB.prepare('SELECT status,COUNT(*) n FROM applications GROUP BY status').all();return json({...r,applications_by_status:by.results})}
 if(a==='jobs'){
  if(M==='GET')return json((await env.DB.prepare('SELECT * FROM jobs ORDER BY updated_at DESC LIMIT 200').all()).results);
  let b={};if(M!=='DELETE'){try{b=await body(req)}catch{return fail('Invalid JSON')}}
  const F=['logo_key','title','company','company_info','location','employment_type','description','responsibilities','requirements','deadline','status','currency','salary_type','work_mode','country','state','city','skills','experience_level','benefits'],I=['category_id','salary_min','salary_max','vacancies','featured'];
  if(M==='POST'){if(!s(b.title)||!s(b.company)||!s(b.location)||!s(b.description,10000))return fail('title, company, location, description required',422);
   const r=await env.DB.prepare(`INSERT INTO jobs(${[...F,...I].join(',')}) VALUES(${[...F,...I].map(()=>'?').join(',')})`).bind(...F.map(k=>s(b[k],10000)||(k==='status'?'draft':k==='employment_type'?'Full Time':k==='salary_type'?'range':null)),...I.map(k=>Number.isFinite(+b[k])&&b[k]!==''&&b[k]!=null?+b[k]:(k==='vacancies'?1:null))).run();
   await audit(env,req,au,'job.create','jobs',r.meta.last_row_id);return json({id:r.meta.last_row_id},201)}
  if(!id)return fail('id required',422);
  if(M==='PATCH'){const sets=[],p=[];for(const k of F)if(k in b){sets.push(k+'=?');p.push(s(b[k],10000)||null)}for(const k of I)if(k in b){sets.push(k+'=?');p.push(b[k]===''||b[k]==null?null:+b[k])}
   if(!sets.length)return fail('Nothing to update',422);
   await env.DB.prepare(`UPDATE jobs SET ${sets.join(',')},updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(...p,id).run();await audit(env,req,au,'job.update','jobs',id);return json({ok:true})}
  if(M==='DELETE'){await env.DB.prepare('DELETE FROM jobs WHERE id=?').bind(id).run();await audit(env,req,au,'job.delete','jobs',id);return json({ok:true})}}
 if(a==='applications'){
  if(M==='GET'&&!id){const q=url.searchParams,w=['1=1'],p=[],st=s(q.get('status'),30),kw=s(q.get('q'),80);
   if(st){w.push('a.status=?');p.push(st)}if(kw){w.push('(a.full_name LIKE ? OR a.email LIKE ? OR a.reference LIKE ?)');const l=`%${kw.replace(/[%_]/g,'')}%`;p.push(l,l,l)}
   const page=Math.max(1,parseInt(q.get('page'))||1);
   const r=await env.DB.prepare(`SELECT a.id,a.reference,a.full_name,a.email,a.status,a.created_at,j.title job_title FROM applications a JOIN jobs j ON j.id=a.job_id WHERE ${w.join(' AND ')} ORDER BY a.created_at DESC LIMIT 25 OFFSET ?`).bind(...p,(page-1)*25).all();return json({applications:r.results,page})}
  if(!id)return fail('id required',422);
  if(M==='GET'&&seg[4]==='cv'){const x=await env.DB.prepare('SELECT cv_key FROM applications WHERE id=?').bind(id).first();if(!x)return fail('Not found',404);
   const exp=Date.now()+300000,sig=await hmac(env,x.cv_key+exp);await audit(env,req,au,'cv.access','applications',id);
   return json({url:`/api/admin/cvfile?k=${encodeURIComponent(x.cv_key)}&e=${exp}&sig=${sig}`,expires_in:300})}
  if(M==='GET'){const x=await env.DB.prepare('SELECT id,reference,job_id,full_name,email,phone,location,education,experience,skills,cover_letter,status,created_at FROM applications WHERE id=?').bind(id).first();if(!x)return fail('Not found',404);
   const n=await env.DB.prepare('SELECT note,created_at FROM application_notes WHERE application_id=? ORDER BY id DESC').bind(id).all();return json({...x,notes:n.results})}
  let b;try{b=await body(req)}catch{return fail('Invalid JSON')}
  if(M==='PATCH'){const ok=['Pending','Under Review','Shortlisted','Interview Scheduled','Accepted','Rejected'];if(!ok.includes(b.status))return fail('Invalid status',422);
   await env.DB.prepare('UPDATE applications SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(b.status,id).run();await audit(env,req,au,'application.status','applications',id);return json({ok:true})}
  if(M==='POST'&&seg[4]==='notes'){if(!s(b.note,2000))return fail('Note required',422);await env.DB.prepare('INSERT INTO application_notes(application_id,admin_id,note) VALUES(?,?,?)').bind(id,au.uid,s(b.note,2000)).run();return json({ok:true},201)}}
 if(a==='cvfile'&&M==='GET'){const k=url.searchParams.get('k')||'',e=+url.searchParams.get('e'),sg=url.searchParams.get('sig')||'';
  if(!k.startsWith('private/cv/')||e<Date.now()||sg!==await hmac(env,k+e))return fail('Link invalid or expired',403);
  const o=await env.MEDIA_BUCKET.get(k);if(!o)return fail('Not found',404);
  return new Response(o.body,{headers:{'content-type':o.httpMetadata?.contentType||'application/octet-stream','content-disposition':'attachment','cache-control':'private, no-store',...SEC}})}
 if(a==='inquiries'&&M==='GET')return json((await env.DB.prepare('SELECT * FROM employer_inquiries ORDER BY created_at DESC LIMIT 100').all()).results);
 if(a==='inquiries'&&M==='PATCH'&&id){let b;try{b=await body(req)}catch{return fail('Invalid JSON')}
  if(!['New','Contacted','In Progress','Closed','Archived'].includes(b.status))return fail('Invalid status',422);
  await env.DB.prepare('UPDATE employer_inquiries SET status=?,admin_notes=COALESCE(?,admin_notes) WHERE id=?').bind(b.status,b.admin_notes?s(b.admin_notes,2000):null,id).run();return json({ok:true})}
 if(a==='services'){
  const SF=['slug','name','description','full_description','audience','benefits','how_it_works','image_key','icon'];
  if(M==='GET')return json((await env.DB.prepare('SELECT * FROM services ORDER BY sort_order,id').all()).results);
  let b={};if(M!=='DELETE'){try{b=await body(req)}catch{return fail('Invalid JSON')}}
  const jv=k=>(k==='benefits'||k==='how_it_works')?JSON.stringify(Array.isArray(b[k])?b[k].map(x=>s(x,300)).filter(Boolean):[]):(s(b[k],5000)||null);
  if(M==='POST'){if(!s(b.name)||!s(b.description))return fail('name and description required',422);
   const slug=s(b.slug,80)||s(b.name,80).toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
   const r=await env.DB.prepare(`INSERT INTO services(${SF.join(',')},active,sort_order) VALUES(${SF.map(()=>'?').join(',')},?,?)`).bind(...SF.map(k=>k==='slug'?slug:jv(k)),b.active===0?0:1,parseInt(b.sort_order)||0).run();
   await audit(env,req,au,'service.create','services',r.meta.last_row_id);return json({id:r.meta.last_row_id},201)}
  if(!id)return fail('id required',422);
  if(M==='PATCH'){const sets=[],p=[];for(const k of SF)if(k in b&&k!=='slug'){sets.push(k+'=?');p.push(jv(k))}
   if('active' in b){sets.push('active=?');p.push(b.active?1:0)}if('sort_order' in b){sets.push('sort_order=?');p.push(parseInt(b.sort_order)||0)}
   if(!sets.length)return fail('Nothing to update',422);await env.DB.prepare(`UPDATE services SET ${sets.join(',')} WHERE id=?`).bind(...p,id).run();await audit(env,req,au,'service.update','services',id);return json({ok:true})}
  if(M==='DELETE'){await env.DB.prepare('DELETE FROM services WHERE id=?').bind(id).run();await audit(env,req,au,'service.delete','services',id);return json({ok:true})}}
 if(a==='service-requests'){
  if(M==='GET'){const q=url.searchParams,w=['r.archived=?'],p=[q.get('archived')==='1'?1:0],st=s(q.get('status'),20),kw=s(q.get('q'),80);
   if(st){w.push('r.status=?');p.push(st)}if(kw){w.push('(r.full_name LIKE ? OR r.email LIKE ? OR r.reference LIKE ?)');const l=`%${kw.replace(/[%_]/g,'')}%`;p.push(l,l,l)}
   const page=Math.max(1,parseInt(q.get('page'))||1);
   return json({requests:(await env.DB.prepare(`SELECT r.*,sv.name service FROM service_requests r JOIN services sv ON sv.id=r.service_id WHERE ${w.join(' AND ')} ORDER BY r.created_at DESC LIMIT 25 OFFSET ?`).bind(...p,(page-1)*25).all()).results,page})}
  if(M==='PATCH'&&id){let b;try{b=await body(req)}catch{return fail('Invalid JSON')}const sets=[],p=[];
   if('status' in b){if(!['New','In Progress','Completed','Cancelled'].includes(b.status))return fail('Invalid status',422);sets.push('status=?');p.push(b.status)}
   if('admin_notes' in b){sets.push('admin_notes=?');p.push(s(b.admin_notes,2000))}if('archived' in b){sets.push('archived=?');p.push(b.archived?1:0)}
   if(!sets.length)return fail('Nothing to update',422);await env.DB.prepare(`UPDATE service_requests SET ${sets.join(',')} WHERE id=?`).bind(...p,id).run();await audit(env,req,au,'service_request.update','service_requests',id);return json({ok:true})}}
 if(a==='media'&&M==='POST'){
  if(+req.headers.get('content-length')>4*1024*1024)return fail('File too large (max 3MB)',413);
  const f=await req.formData(),file=f.get('file'),kind=['service','logo','banner','general'].includes(f.get('kind'))?f.get('kind'):'general';
  if(!(file instanceof File)||!file.size||file.size>3*1024*1024)return fail('Image required (max 3MB)',422);
  const sg=hex(new Uint8Array(await file.slice(0,4).arrayBuffer())),t=sg.startsWith('ffd8ff')?['image/jpeg','jpg']:sg==='89504e47'?['image/png','png']:sg==='52494646'?['image/webp','webp']:null;
  if(!t||file.type!==t[0])return fail('Only PNG, JPEG or WebP images',422);
  const key=`public/${kind}/${rnd(10)}.${t[1]}`;await env.MEDIA_BUCKET.put(key,file.stream(),{httpMetadata:{contentType:t[0]}});
  await env.DB.prepare('INSERT INTO media_assets(r2_key,kind,mime,size,uploaded_by) VALUES(?,?,?,?,?)').bind(key,kind,t[0],file.size,au.uid).run();await audit(env,req,au,'media.upload','media_assets',key);return json({key},201)}

 if(a==='categories'){
  if(M==='GET')return json((await env.DB.prepare('SELECT * FROM job_categories ORDER BY sort_order,name').all()).results);
  let b={};if(M!=='DELETE'){try{b=await body(req)}catch{return fail('Invalid JSON')}}
  const slugOf=n=>n.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
  try{
   if(M==='POST'){const n=s(b.name,80);if(!n)return fail('Name required',422);const r=await env.DB.prepare('INSERT INTO job_categories(name,slug,sort_order) VALUES(?,?,?)').bind(n,slugOf(n),parseInt(b.sort_order)||0).run();await audit(env,req,au,'category.create','job_categories',r.meta.last_row_id);return json({id:r.meta.last_row_id},201)}
   if(!id)return fail('id required',422);
   if(M==='PATCH'){const n=s(b.name,80);if(!n)return fail('Name required',422);await env.DB.prepare('UPDATE job_categories SET name=?,slug=? WHERE id=?').bind(n,slugOf(n),id).run();await audit(env,req,au,'category.update','job_categories',id);return json({ok:true})}
   if(M==='DELETE'){await env.DB.prepare('DELETE FROM job_categories WHERE id=?').bind(id).run();await audit(env,req,au,'category.delete','job_categories',id);return json({ok:true})}
  }catch(e){return fail('That category name already exists',409)}}
 if(a==='banners'){
  const BF=['image_key','headline','subtitle','link','starts_at','ends_at'];
  if(M==='GET')return json((await env.DB.prepare('SELECT * FROM homepage_banners ORDER BY sort_order,id').all()).results);
  let b={};if(M!=='DELETE'){try{b=await body(req)}catch{return fail('Invalid JSON')}}
  const v=k=>{const x=s(b[k],500)||null;if(!x)return null;if(k==='link'&&!/^(#|\/|https:\/\/)/.test(x))return null;if(k==='image_key'&&!/^public\/banner\/[a-f0-9]+\.(png|jpg|webp)$/.test(x))return null;return x};
  if(M==='POST'){if(!v('image_key'))return fail('Upload a banner image first',422);
   const r=await env.DB.prepare(`INSERT INTO homepage_banners(${BF.join(',')},sort_order,active) VALUES(${BF.map(()=>'?').join(',')},?,?)`).bind(...BF.map(v),parseInt(b.sort_order)||0,b.active===0||b.active===false?0:1).run();
   await audit(env,req,au,'banner.create','homepage_banners',r.meta.last_row_id);return json({id:r.meta.last_row_id},201)}
  if(!id)return fail('id required',422);
  if(M==='PATCH'){const sets=[],p=[];for(const k of BF)if(k in b){if(k==='image_key'&&!v(k))continue;sets.push(k+'=?');p.push(v(k))}
   if('sort_order' in b){sets.push('sort_order=?');p.push(parseInt(b.sort_order)||0)}if('active' in b){sets.push('active=?');p.push(b.active?1:0)}
   if(!sets.length)return fail('Nothing to update',422);await env.DB.prepare(`UPDATE homepage_banners SET ${sets.join(',')} WHERE id=?`).bind(...p,id).run();await audit(env,req,au,'banner.update','homepage_banners',id);return json({ok:true})}
  if(M==='DELETE'){await env.DB.prepare('DELETE FROM homepage_banners WHERE id=?').bind(id).run();await audit(env,req,au,'banner.delete','homepage_banners',id);return json({ok:true})}}

 return fail('Not found',404)}
