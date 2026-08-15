# pentect-plugin

Dependency-free Python helpers for a Pentect Command plugin.

```python
from pentect_plugin import serve

def inspect(request):
    return {"spans": []}

serve(inspect)
```

See <https://pentect.dev/plugins/command/>.
