from pathlib import Path
import csv, io, json
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Any
from .engine import analyze_logs
from .ml import evaluate_model

ROOT=Path(__file__).resolve().parents[1]
app=FastAPI(title="SentinelScope Security Analytics", version="1.0.0", description="Educational cybersecurity log detection, alert correlation, and compliance mapping prototype")
app.mount("/static",StaticFiles(directory=ROOT/"app"/"static"),name="static")
class AnalyzeRequest(BaseModel):
    logs: list[dict[str, Any]] = Field(..., min_length=1, max_length=5000)
@app.get("/", response_class=HTMLResponse)
def home(): return (ROOT/"app"/"static"/"index.html").read_text(encoding="utf-8")
@app.get("/api/health")
def health(): return {"status":"ok","service":"SentinelScope Security Analytics","version":"1.0.0"}
@app.get("/api/sample-logs")
def sample_logs(): return json.loads((ROOT/"data"/"sample_logs.json").read_text(encoding="utf-8"))
@app.get("/api/dashboard")
def dashboard():
    logs=json.loads((ROOT/"data"/"sample_logs.json").read_text(encoding="utf-8")); result=analyze_logs(logs)
    return {**result,"model_metrics":evaluate_model()}
@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):
    try: return analyze_logs(request.logs)
    except Exception as e: raise HTTPException(status_code=500, detail=f"Analysis failed: {type(e).__name__}: {e}")
@app.post("/api/upload-csv")
async def upload_csv(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith('.csv'): raise HTTPException(status_code=400,detail="Upload a .csv file.")
    raw=await file.read()
    if len(raw)>5_000_000: raise HTTPException(status_code=413,detail="File is too large; maximum size is 5 MB.")
    try:
        text=raw.decode('utf-8-sig'); reader=csv.DictReader(io.StringIO(text))
        required={'timestamp','event_type','source_ip','asset','severity','message'}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)): raise ValueError("CSV must include columns: " + ', '.join(sorted(required)))
        rows=list(reader)
        if not rows: raise ValueError("CSV has no data rows.")
        if len(rows)>5000: raise ValueError("Maximum 5,000 log rows per upload.")
        return analyze_logs(rows)
    except (UnicodeDecodeError, csv.Error, ValueError) as e: raise HTTPException(status_code=400,detail=str(e))
@app.get("/api/model-metrics")
def model_metrics(): return evaluate_model()
@app.post("/api/report")
def report(request: AnalyzeRequest):
    result=analyze_logs(request.logs)
    report_data={"report_title":"SentinelScope Security Assessment Report","generated_at":"Generated at request time","disclaimer":"Prototype output for triage support only. Validate alerts and compliance interpretations with a qualified security professional.",**result}
    return JSONResponse(report_data,headers={"Content-Disposition":"attachment; filename=sentinelscope-security-report.json"})
