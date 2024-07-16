#!/bin/sh

echo "Waiting for postgres..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 0.1
done
echo "PostgreSQL started"

cd /usr/src/

python3 manage.py flush --no-input
python manage.py makemigrations
python3 manage.py migrate
python3 manage.py collectstatic --noinput

#! ONLY IN DEBUG
#python manage.py runserver
exec "$@"