"""REACT AI local incident response API. Demo actions are simulated and allowlisted."""
from __future__ import annotations
import hashlib, hmac, json, os, secrets, time
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, Float, Text, DateTime, ForeignKey, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./react_ai.db")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine, expire_on_commit=False)
SECRET = os.getenv("APP_SECRET", "local-demo-secret-change-me")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "reactai-demo")

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__="users"
    id: Mapped[int]=mapped_column(primary_key=True); username: Mapped[str]=mapped_column(String, unique=True); password_hash: Mapped[str]=mapped_column(String); role: Mapped[str]=mapped_column(String, default="operator")
class Incident(Base):
    __tablename__="incidents"
    id: Mapped[str]=mapped_column(String, primary_key=True); fingerprint: Mapped[str]=mapped_column(String, index=True); title: Mapped[str]=mapped_column(String); severity: Mapped[str]=mapped_column(String, index=True); status: Mapped[str]=mapped_column(String, default="ACTIVE"); service: Mapped[str]=mapped_column(String); detected_at: Mapped[datetime]=mapped_column(DateTime, default=lambda: datetime.now(timezone.utc)); resolved_at: Mapped[Optional[datetime]]=mapped_column(DateTime, nullable=True); log_text: Mapped[str]=mapped_column(Text); root_cause: Mapped[str]=mapped_column(Text, default="Investigation pending"); evidence: Mapped[str]=mapped_column(Text, default="[]"); confidence: Mapped[float]=mapped_column(Float, default=0); recommendation: Mapped[str]=mapped_column(Text, default="Collect more evidence"); recovery_status: Mapped[str]=mapped_column(String, default="NOT_PROPOSED"); occurrences: Mapped[int]=mapped_column(Integer, default=1)
class Log(Base):
    __tablename__="logs"
    id: Mapped[int]=mapped_column(primary_key=True); timestamp: Mapped[datetime]=mapped_column(DateTime, default=lambda: datetime.now(timezone.utc)); service: Mapped[str]=mapped_column(String); level: Mapped[str]=mapped_column(String); message: Mapped[str]=mapped_column(Text); source: Mapped[str]=mapped_column(String, default="simulated"); incident_id: Mapped[Optional[str]]=mapped_column(ForeignKey("incidents.id"), nullable=True)
class AgentRun(Base):
    __tablename__="agent_runs"
    id: Mapped[int]=mapped_column(primary_key=True); incident_id: Mapped[Optional[str]]=mapped_column(String); agent: Mapped[str]=mapped_column(String); status: Mapped[str]=mapped_column(String); detail: Mapped[str]=mapped_column(Text); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
class Recovery(Base):
    __tablename__="recovery_plans"
    id: Mapped[int]=mapped_column(primary_key=True); incident_id: Mapped[str]=mapped_column(ForeignKey("incidents.id")); action: Mapped[str]=mapped_column(String); status: Mapped[str]=mapped_column(String, default="PENDING_APPROVAL"); approved_by: Mapped[Optional[str]]=mapped_column(String, nullable=True); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
class Audit(Base):
    __tablename__="audit_events"
    id: Mapped[int]=mapped_column(primary_key=True); actor: Mapped[str]=mapped_column(String); event: Mapped[str]=mapped_column(String); incident_id: Mapped[Optional[str]]=mapped_column(String); detail: Mapped[str]=mapped_column(Text); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
class Metric(Base):
    __tablename__="metrics"
    id: Mapped[int]=mapped_column(primary_key=True); cpu: Mapped[float]=mapped_column(Float); memory: Mapped[float]=mapped_column(Float); health: Mapped[float]=mapped_column(Float); simulated: Mapped[int]=mapped_column(Integer, default=0); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
Base.metadata.create_all(engine)
with SessionLocal() as s:
    if not s.scalar(select(User).where(User.username=="admin")):
        salt=secrets.token_hex(16); digest=hashlib.pbkdf2_hmac("sha256", DEMO_PASSWORD.encode(), salt.encode(), 180000).hex(); s.add(User(username="admin", password_hash=f"{salt}${digest}", role="admin")); s.commit()

app=FastAPI(title="REACT AI", version="1.0.0", description="Local demo incident detection and human-approved recovery API")
app.add_middleware(CORSMiddleware, allow_origins=[os.getenv("FRONTEND_ORIGIN","http://localhost:5173")], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()
def token(user):
    payload=f"{user.username}:{user.role}:{int(time.time())+86400}"; sig=hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest(); return f"{payload}:{sig}"
def current(authorization: Optional[str]=Header(None), s: Session=Depends(db)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Login required")
    try:
        username,role,expires,sig=authorization[7:].rsplit(":",3); payload=f"{username}:{role}:{expires}"
        if int(expires)<time.time() or not hmac.compare_digest(sig,hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()): raise ValueError()
        u=s.scalar(select(User).where(User.username==username))
        if not u or u.role!=role: raise ValueError()
        return u
    except Exception: raise HTTPException(401,"Invalid or expired session")
def admin(u: User=Depends(current)):
    if u.role!="admin": raise HTTPException(403,"Administrator role required")
    return u
def stamp(dt): return dt.isoformat() if dt else None
def incident_json(i): return {"id":i.id,"title":i.title,"severity":i.severity,"status":i.status,"service":i.service,"detected_at":stamp(i.detected_at),"resolved_at":stamp(i.resolved_at),"log_text":i.log_text,"root_cause":i.root_cause,"evidence":json.loads(i.evidence),"confidence":i.confidence,"recommendation":i.recommendation,"recovery_status":i.recovery_status,"occurrences":i.occurrences}
def audit(s, actor, event, incident_id=None, detail=""):
    s.add(Audit(actor=actor,event=event,incident_id=incident_id,detail=detail)); s.flush()
def run(s, incident_id, agent, detail): s.add(AgentRun(incident_id=incident_id,agent=agent,status="completed",detail=detail))
def analyze(s,i):
    msg=i.log_text.lower(); clues=[]
    rules=[("database", "Database connection exhaustion or unreachable database", "Check database availability and connection pool limits", .84, ["Database connection error present","Service could not obtain a database connection"]),("cpu", "High CPU saturation is a likely cause", "Inspect hot processes and scale or restart the affected demo service", .79,["CPU threshold event present"]),("memory", "Memory pressure or leak is a likely cause", "Inspect memory growth and restart the simulated service", .78,["Memory exhaustion warning present"]),("500", "Application exception caused repeated HTTP 500 responses", "Inspect application traceback and roll back the last demo deployment", .73,["HTTP 500 response present"]),("unavailable", "The service became unavailable; underlying cause is not yet conclusive", "Check service health and dependency connectivity", .58,["Service unavailable event present"])]
    match=next((r for key,*r in rules if key in msg),None)
    if match: i.root_cause,i.recommendation,i.confidence,clues=match
    else: i.root_cause="Insufficient evidence to identify a probable cause"; i.recommendation="Collect service logs and dependency health before acting"; i.confidence=.25; clues=["No known signature matched"]
    i.evidence=json.dumps(clues); i.recovery_status="PENDING_APPROVAL"
    action="restart_demo_service" if "restart" in i.recommendation.lower() else "restore_demo_dependency"
    s.add(Recovery(incident_id=i.id,action=action)); run(s,i.id,"Investigation Agent",f"{i.root_cause} (confidence {i.confidence:.0%})"); run(s,i.id,"Memory Agent","Searched prior incidents using service and error signature"); run(s,i.id,"Recovery Agent",f"Proposed allowlisted action: {action}; approval required"); run(s,i.id,"AI Commander","Coordinated investigation, memory lookup, and guarded recovery proposal"); s.flush()

class Login(BaseModel): username: str; password: str
class Ingest(BaseModel): service: str=Field(min_length=1,max_length=100); level: str=Field(default="ERROR"); message: str=Field(min_length=1,max_length=5000); source: str=Field(default="api", max_length=30)
SCENARIOS=[("api-gateway","ERROR","HTTP 500 error: unhandled exception in request handler","HIGH"),("postgres","ERROR","Database connection failure: connection pool exhausted","CRITICAL"),("worker","WARN","High CPU usage sustained above 95 percent","HIGH"),("cache","WARN","Memory exhaustion warning: available memory below 5 percent","CRITICAL"),("payments","ERROR","Service unavailable: upstream dependency timeout","MEDIUM")]
@app.get("/api/health")
def health(): return {"status":"ok","mode":"local demo","database":"sqlite" if DB_URL.startswith("sqlite") else "configured"}
@app.post("/api/auth/login")
def login(body: Login,s:Session=Depends(db)):
    u=s.scalar(select(User).where(User.username==body.username))
    if not u: raise HTTPException(401,"Invalid username or password")
    try: salt,digest=u.password_hash.split("$"); actual=hashlib.pbkdf2_hmac("sha256",body.password.encode(),salt.encode(),180000).hex()
    except ValueError: raise HTTPException(401,"Invalid username or password")
    if not hmac.compare_digest(actual,digest): raise HTTPException(401,"Invalid username or password")
    return {"access_token":token(u),"token_type":"bearer","username":u.username,"role":u.role}
@app.get("/api/dashboard/summary")
def summary(s:Session=Depends(db),u:User=Depends(current)):
    all_i=list(s.scalars(select(Incident))); active=[i for i in all_i if i.status!="RESOLVED"]; metrics=list(s.scalars(select(Metric).order_by(Metric.id.desc()).limit(30)))
    cpu=metrics[0].cpu if metrics else 0; mem=metrics[0].memory if metrics else 0
    return {"total_incidents":len(all_i),"active_incidents":len(active),"critical_incidents":sum(i.severity=="CRITICAL" for i in active),"resolved_incidents":sum(i.status=="RESOLVED" for i in all_i),"health":round(max(0,100-len(active)*12),1),"cpu":cpu,"memory":mem,"trend":[{"time":m.created_at.strftime("%H:%M"),"cpu":m.cpu,"memory":m.memory} for m in reversed(metrics)],"agents":agent_status(s),"recent":[incident_json(i) for i in sorted(all_i,key=lambda x:x.detected_at,reverse=True)[:8]]}
def agent_status(s):
    names=["Detection Agent","Investigation Agent","Memory Agent","Recovery Agent","AI Commander"]
    return [{"name":n,"status":"ready","last_run":stamp(s.scalar(select(func.max(AgentRun.created_at)).where(AgentRun.agent==n)))} for n in names]
@app.get("/api/incidents")
def incidents(severity:Optional[str]=None,q:Optional[str]=None,s:Session=Depends(db),u:User=Depends(current)):
    rows=list(s.scalars(select(Incident).order_by(Incident.detected_at.desc())))
    if severity: rows=[i for i in rows if i.severity==severity.upper()]
    if q: rows=[i for i in rows if q.lower() in (i.id+i.title+i.service+i.log_text).lower()]
    return [incident_json(i) for i in rows]
@app.get("/api/incidents/{id}")
def get_incident(id:str,s:Session=Depends(db),u:User=Depends(current)):
    i=s.get(Incident,id)
    if not i: raise HTTPException(404,"Incident not found")
    similar=list(s.scalars(select(Incident).where(Incident.id!=id,Incident.service==i.service).order_by(Incident.detected_at.desc()).limit(5)))
    return {**incident_json(i),"similar":[{**incident_json(x),"similarity":round(.7 if x.fingerprint==i.fingerprint else .55,2)} for x in similar],"history":[{**incident_json(x)} for x in list(s.scalars(select(Incident).where(Incident.service==i.service).order_by(Incident.detected_at.desc()).limit(15)))],"runs":[{"agent":r.agent,"status":r.status,"detail":r.detail,"created_at":stamp(r.created_at)} for r in s.scalars(select(AgentRun).where(AgentRun.incident_id==id).order_by(AgentRun.created_at.desc()))],"recovery_plans":[{"id":r.id,"action":r.action,"status":r.status,"approved_by":r.approved_by,"created_at":stamp(r.created_at)} for r in s.scalars(select(Recovery).where(Recovery.incident_id==id))]}
def process(body:Ingest,s:Session,actor="system"):
    fingerprint=hashlib.sha256((body.service.lower()+":"+body.message.lower().split(":")[0]).encode()).hexdigest(); i=s.scalar(select(Incident).where(Incident.fingerprint==fingerprint,Incident.status!="RESOLVED"))
    level=body.level.upper(); sev=level if level in ["LOW","MEDIUM","HIGH","CRITICAL"] else ("CRITICAL" if any(k in body.message.lower() for k in ["exhausted","exhaustion","unavailable"]) else "HIGH")
    if i: i.occurrences+=1; i.log_text += "\n"+body.message
    else:
        i=Incident(id="INC-"+secrets.token_hex(4).upper(),fingerprint=fingerprint,title=body.message[:85],severity=sev,service=body.service,log_text=body.message); s.add(i); s.flush(); analyze(s,i)
    s.add(Log(service=body.service,level=level,message=body.message,source=body.source,incident_id=i.id)); run(s,None,"Detection Agent",f"Ingested {body.source} event for {body.service}; {'deduplicated' if i.occurrences>1 else 'created '+i.id}"); audit(s,actor,"LOG_INGESTED",i.id,f"{body.service}: {body.message[:200]}"); s.commit(); s.refresh(i); return incident_json(i)
@app.post("/api/logs/ingest")
def ingest(body:Ingest,s:Session=Depends(db),u:User=Depends(current)): return process(body,s,u.username)
@app.get("/api/logs")
def logs(limit:int=100,s:Session=Depends(db),u:User=Depends(current)):
    return [{"id":x.id,"timestamp":stamp(x.timestamp),"service":x.service,"level":x.level,"message":x.message,"source":x.source,"incident_id":x.incident_id} for x in s.scalars(select(Log).order_by(Log.id.desc()).limit(min(limit,500)))]
@app.post("/api/demo/generate")
def demo(count:int=Query(default=1,ge=1,le=5),s:Session=Depends(db),u:User=Depends(current)):
    result=[]
    for service,level,message,sev in [SCENARIOS[(int(time.time()*1000)+j)%len(SCENARIOS)] for j in range(count)]: result.append(process(Ingest(service=service,level=sev,message=message,source="simulated"),s,u.username))
    cpu=secrets.randbelow(40)+20; mem=secrets.randbelow(35)+30
    s.add(Metric(cpu=cpu,memory=mem,health=max(10,100-scalar_active(s)*12),simulated=1)); audit(s,u.username,"DEMO_GENERATED",None,f"Generated {count} simulated events"); s.commit(); return {"generated":len(result),"incidents":result,"source":"simulated"}
def scalar_active(s): return s.scalar(select(func.count()).select_from(Incident).where(Incident.status!="RESOLVED")) or 0
@app.post("/api/agents/investigate/{id}")
def investigate(id:str,s:Session=Depends(db),u:User=Depends(current)):
    i=s.get(Incident,id)
    if not i: raise HTTPException(404,"Incident not found")
    analyze(s,i); audit(s,u.username,"INVESTIGATION_RUN",id,"Rule-based investigation refreshed"); s.commit(); return get_incident(id,s,u)
@app.get("/api/agents/status")
def agents(s:Session=Depends(db),u:User=Depends(current)): return agent_status(s)
def plan(s,id):
    i=s.get(Incident,id)
    if not i: raise HTTPException(404,"Incident not found")
    r=s.scalar(select(Recovery).where(Recovery.incident_id==id).order_by(Recovery.id.desc()))
    if not r: r=Recovery(incident_id=id,action="restart_demo_service"); s.add(r); s.flush()
    return i,r
@app.post("/api/recovery/approve/{id}")
def approve(id:str,s:Session=Depends(db),u:User=Depends(admin)):
    i,r=plan(s,id)
    if r.status!="PENDING_APPROVAL": raise HTTPException(409,f"Plan is {r.status}")
    r.status="APPROVED";r.approved_by=u.username;i.recovery_status="APPROVED";audit(s,u.username,"RECOVERY_APPROVED",id,r.action);s.commit();return {"plan_id":r.id,"status":r.status,"action":r.action}
@app.post("/api/recovery/reject/{id}")
def reject(id:str,s:Session=Depends(db),u:User=Depends(admin)):
    i,r=plan(s,id)
    if r.status!="PENDING_APPROVAL": raise HTTPException(409,f"Plan is {r.status}")
    r.status="REJECTED";i.recovery_status="REJECTED";audit(s,u.username,"RECOVERY_REJECTED",id,r.action);s.commit();return {"status":r.status}
@app.post("/api/recovery/execute/{id}")
def execute(id:str,s:Session=Depends(db),u:User=Depends(admin)):
    i,r=plan(s,id)
    if r.status!="APPROVED": raise HTTPException(409,"Human approval is required before execution")
    if r.action not in {"restart_demo_service","restore_demo_dependency"}: raise HTTPException(400,"Action is not allowlisted")
    # Simulated recovery only: no shell command or infrastructure call is made.
    r.status="EXECUTED";i.status="RESOLVED";i.recovery_status="VERIFIED_SIMULATED";i.resolved_at=datetime.now(timezone.utc);audit(s,u.username,"RECOVERY_EXECUTED_SIMULATED",id,f"{r.action}; simulated health verification passed");run(s,id,"Recovery Agent","Executed in isolated demo state; simulated health verification passed");s.commit();return {"status":r.status,"incident_status":i.status,"verified":True,"mode":"simulation"}
@app.post("/api/incidents/{id}/resolve")
def resolve(id:str,s:Session=Depends(db),u:User=Depends(current)):
    i=s.get(Incident,id)
    if not i: raise HTTPException(404,"Incident not found")
    i.status="RESOLVED";i.resolved_at=datetime.now(timezone.utc);i.recovery_status="MANUALLY_RESOLVED";audit(s,u.username,"INCIDENT_RESOLVED",id,"Operator marked resolved");s.commit();return incident_json(i)
@app.get("/api/audit")
def audits(s:Session=Depends(db),u:User=Depends(current)):
    return [{"id":x.id,"actor":x.actor,"event":x.event,"incident_id":x.incident_id,"detail":x.detail,"created_at":stamp(x.created_at)} for x in s.scalars(select(Audit).order_by(Audit.id.desc()).limit(500))]
@app.get("/api/metrics")
def metrics(s:Session=Depends(db),u:User=Depends(current)):
    try:
        import psutil; cpu=psutil.cpu_percent(interval=.05); memory=psutil.virtual_memory().percent; mode="host"
    except Exception: cpu=memory=0; mode="unavailable"
    s.add(Metric(cpu=cpu,memory=memory,health=max(0,100-scalar_active(s)*12),simulated=0));s.commit()
    return {"cpu":cpu,"memory":memory,"health":max(0,100-scalar_active(s)*12),"mode":mode,"sampled_at":datetime.now(timezone.utc).isoformat()}

# Docker build serves the compiled SPA from the same origin. In local development Vite serves it.
STATIC_DIR=os.path.abspath(os.path.join(os.path.dirname(__file__),"..","static"))
if os.path.isdir(STATIC_DIR):
    from fastapi.staticfiles import StaticFiles
    @app.get("/", include_in_schema=False)
    def home(): return FileResponse(os.path.join(STATIC_DIR,"index.html"))
    app.mount("/assets",StaticFiles(directory=os.path.join(STATIC_DIR,"assets")),name="assets")
