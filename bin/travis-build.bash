#!/bin/bash
set -e

echo "This is travis-build.bash..."

echo "Installing ckanext-georchestra and its requirements..."
python setup.py develop
pip install -r requirements.txt
pip install -r dev-requirements.txt

echo "Moving test.ini into a subdir..."
mkdir subdir
mv test.ini subdir
# update the path to test-core.ini
sed -i -e 's|/usr/lib/ckan/lib/default/src/ckan/test-core.ini|../ckan/test-core.ini|' subdir/test.ini

echo "travis-build.bash is done."
