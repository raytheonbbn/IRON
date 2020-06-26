# How the rest of build should look
tar xvfz gulp.tgz
gunzip 01-gulp-amd64.patch.gz 
patch -p1 < 01-gulp-amd64.patch
gunzip 02-gulp-ntGFZ.patch.gz
patch -p1 < 02-gulp-ntGFZ.patch
make

