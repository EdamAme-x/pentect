from engine.core import PentectEngine


def test_har_masking_end_to_end():
    har = """
    {"log":{"version":"1.2","creator":{"name":"t","version":"1"},"entries":[
      {"startedDateTime":"2026-04-19T10:00:00.000Z","time":1,
       "request":{"method":"GET","url":"http://jira.corp.internal/api/issues/1001",
                  "httpVersion":"HTTP/1.1","cookies":[],
                  "headers":[{"name":"Authorization","value":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_long_part_xyz"}],
                  "queryString":[],"headersSize":-1,"bodySize":0},
       "response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","cookies":[],
                   "headers":[],
                   "content":{"size":10,"mimeType":"application/json",
                              "text":"{\\"ip\\":\\"10.0.5.42\\"}"},
                   "redirectURL":"","headersSize":-1,"bodySize":10},
       "cache":{},"timings":{"send":1,"wait":1,"receive":1}}
    ]}}
    """
    engine = PentectEngine(use_llm=False)
    result = engine.mask_har(har)
    masked = result.masked_text
    assert "eyJhbGciOiJIUzI1NiJ9" not in masked
    assert "jira.corp.internal" not in masked
    assert "10.0.5.42" not in masked
    assert result.summary["total_masked"] > 0
