"""업로드한 PE 파일을 LightGBM 모델로 판별하는 Flask 앱.

실행:  python app/app.py   →  http://127.0.0.1:5050
"""
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import lief
import lightgbm as lgb
from ember.features import PEFeatureExtractor
from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MAX_UPLOAD_MB = 200

# 깨진 PE에서 lief가 경고를 대량으로 쏟아내는 것을 막는다
lief.logging.disable()

extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
model = lgb.Booster(model_file=str(DATA_DIR / "ransom_lgbm.txt"))
model_info = json.loads((DATA_DIR / "ransom_lgbm_info.json").read_text())
THRESHOLD = model_info["threshold"]  # 검증 데이터에서 오탐율 0.1%에 맞춘 값

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


def out_of_scope_reason(raw):
    """모델이 학습한 유형(32비트 GUI/콘솔 EXE)이 아니면 그 이유를, 맞으면 None을 돌려준다."""
    coff = raw["header"]["coff"]
    optional = raw["header"]["optional"]
    if not coff["machine"]:
        return "PE 구조를 해석할 수 없는 파일입니다."
    if coff["machine"] != "I386" or optional["magic"] != "PE32":
        return f"32비트 파일만 지원합니다. (이 파일: {coff['machine']}, {optional['magic']})"
    if "DLL" in coff["characteristics"]:
        return "DLL은 지원하지 않습니다. 실행 파일(EXE)만 지원합니다."
    if optional["subsystem"] not in ("WINDOWS_GUI", "WINDOWS_CUI"):
        return f"GUI/콘솔 실행 파일만 지원합니다. (이 파일: {optional['subsystem']})"
    return None


def yes_no(value):
    return "있음" if value else "없음"


def summarize(raw):
    """화면에 보여 줄 파일 정보를 원시 특징에서 꺼낸다."""
    general = raw["general"]
    coff = raw["header"]["coff"]
    optional = raw["header"]["optional"]
    strings = raw["strings"]
    sections = raw["section"]["sections"]

    timestamp = coff["timestamp"]
    try:
        if timestamp == 0:  # 헤더의 날짜가 지워진 파일
            raise ValueError
        built = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        built = "알 수 없음"

    # 파일 전체의 바이트 엔트로피 (0~8, 높을수록 압축·암호화된 내용에 가깝다)
    total = sum(raw["histogram"])
    entropy = -sum(c / total * math.log2(c / total) for c in raw["histogram"] if c)

    groups = [
        {
            "title": "헤더",
            "items": [
                ["CPU 종류", coff["machine"]],
                ["PE 형식", optional["magic"]],
                ["서브시스템", optional["subsystem"]],
                ["파일 종류", "DLL" if "DLL" in coff["characteristics"] else "EXE"],
                ["빌드 날짜(헤더)", built],
                ["링커 버전", f"{optional['major_linker_version']}.{optional['minor_linker_version']}"],
                ["ASLR", yes_no("DYNAMIC_BASE" in optional["dll_characteristics"])],
                ["DEP", yes_no("NX_COMPAT" in optional["dll_characteristics"])],
            ],
        },
        {
            "title": "구조",
            "items": [
                ["파일 엔트로피", f"{entropy:.2f} / 8"],
                ["섹션 수", len(sections)],
                ["진입 섹션", raw["section"]["entry"] or "(없음)"],
                ["가져온 DLL 수", len(raw["imports"])],
                ["가져온 함수 수", general["imports"]],
                ["내보낸 함수 수", general["exports"]],
            ],
        },
        {
            "title": "포함 여부",
            "items": [
                ["디지털 서명", yes_no(general["has_signature"])],
                ["리소스", yes_no(general["has_resources"])],
                ["디버그 정보", yes_no(general["has_debug"])],
                ["재배치 정보", yes_no(general["has_relocations"])],
                ["TLS", yes_no(general["has_tls"])],
            ],
        },
        {
            "title": "문자열",
            "items": [
                ["문자열 수", strings["numstrings"]],
                ["평균 길이", f"{strings['avlength']:.1f}"],
                ["URL", strings["urls"]],
                ["경로(C:\\)", strings["paths"]],
                ["레지스트리 키", strings["registry"]],
                ["내장된 MZ 표식", strings["MZ"]],
            ],
        },
    ]

    section_rows = [
        {
            "name": s["name"] or "(이름 없음)",
            "size": s["size"],
            "vsize": s["vsize"],
            "entropy": round(s["entropy"], 2),
            "access": "".join(
                letter
                for letter, flag in (("R", "MEM_READ"), ("W", "MEM_WRITE"), ("X", "MEM_EXECUTE"))
                if flag in s["props"]
            ),
        }
        for s in sections
    ]
    import_rows = [{"dll": name, "functions": len(functions)} for name, functions in raw["imports"].items()]

    return {"groups": groups, "sections": section_rows, "imports": import_rows}


@app.get("/")
def index():
    return render_template("index.html", threshold=THRESHOLD, max_upload_mb=MAX_UPLOAD_MB)


@app.post("/predict")
def predict():
    upload = request.files.get("file")
    if upload is None or upload.filename == "":
        return jsonify(error="파일이 없습니다."), 400

    # 업로드한 파일은 바이트로 읽기만 한다. 실행하지 않고 따로 저장하지도 않는다.
    data = upload.read()
    if not data:
        return jsonify(error="빈 파일입니다."), 400

    result = {"filename": upload.filename, "size": len(data), "threshold": THRESHOLD}

    if data[:2] != b"MZ":
        result.update(status="unsupported", reason="PE 파일(EXE)이 아닙니다.")
        return jsonify(result)

    raw = extractor.raw_features(data)
    result["sha256"] = raw["sha256"]

    reason = out_of_scope_reason(raw)
    if raw["header"]["coff"]["machine"]:  # PE 구조를 읽을 수 있었으면 판정과 무관하게 정보를 보여 준다
        result["details"] = summarize(raw)
    if reason:
        result.update(status="unsupported", reason=reason)
        return jsonify(result)

    vector = extractor.process_raw_features(raw)
    score = float(model.predict(vector.reshape(1, -1))[0])
    result.update(status="ransomware" if score >= THRESHOLD else "benign", score=score)
    return jsonify(result)


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error=f"파일이 너무 큽니다. 최대 {MAX_UPLOAD_MB}MB까지 올릴 수 있습니다."), 413


if __name__ == "__main__":
    # 악성 샘플을 다루므로 이 컴퓨터에서만 접속할 수 있게 127.0.0.1에 묶는다
    app.run(host="127.0.0.1", port=5050)
