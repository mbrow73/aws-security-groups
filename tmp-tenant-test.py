from pathlib import Path
import shutil
base = Path('/tmp/sg-tenant-test')
if base.exists():
    shutil.rmtree(base)
(base / 'accounts/123456789012/payments').mkdir(parents=True)
shutil.copy('owners.yaml', base / 'owners.yaml')
shutil.copy('guardrails.yaml', base / 'guardrails.yaml')
(base / 'accounts/123456789012/payments/security-groups.yaml').write_text('''account_id: "123456789012"\nenvironment: "dev"\ncarid: "600001725"\nsecurity_groups:\n  app-a:\n    description: "test"\n    ingress: []\n    egress: []\n''')
