FROM postgres:18-alpine
RUN apk add --no-cache python3 py3-pip py3-psycopg2 && python3 -m venv --system-site-packages /opt/patroni && /opt/patroni/bin/pip install --no-cache-dir 'patroni[etcd3]==4.1.0'
ENTRYPOINT ["/opt/patroni/bin/patroni"]
