#!/bin/bash
# Inicializa banco e sobe gunicorn
python -c "from database import init_db; init_db()"
exec gunicorn server:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
