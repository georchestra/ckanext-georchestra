#!/bin/bash
set -e

echo "Installing CKAN and its Python dependencies..."
git clone https://github.com/ckan/ckan
cd ckan
# export latest_ckan_release_branch=`git branch --all | grep remotes/origin/release-v | sort -r | sed 's/remotes\/origin\///g' | head -n 1`
# Last branch tagged as release was 2.6... so, forcing the tag manually
export latest_ckan_release_branch=2.8
echo "CKAN branch: $latest_ckan_release_branch"
git checkout $latest_ckan_release_branch
pip install -r requirement-setuptools.txt
python setup.py develop
pip install -r requirements.txt
pip install -r dev-requirements.txt

echo "Creating the PostgreSQL user and database..."
sudo -u postgres psql -c "CREATE USER ckan_default WITH PASSWORD 'pass';"
sudo -u postgres psql -c 'CREATE DATABASE ckan_test WITH OWNER ckan_default;'

echo "SOLR config..."
# Solr is multicore for tests on ckan master, but it's easier to run tests on
# Travis single-core. See https://github.com/ckan/ckan/issues/2972
sed -i -e 's/solr_url.*/solr_url = http:\/\/127.0.0.1:8983\/solr/' test-core.ini

echo "Initialising the database..."
paster db init -c test-core.ini