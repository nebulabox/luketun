set luketun_dir=c:\codes\luketun
set boost_dir=c:\codes\boost
set zlib_dir=C:\codes\zlib
set bzip2_dir=c:\codes\bzip2

call .\win.env.bat

cd %boost_dir%
call bootstrap.bat

copy %luketun_dir%\win\zconf.h %zlib_dir%

rem Build 64bits static lib
b2 --with-regex --with-date_time --with-program_options --with-iostreams --with-container --with-filesystem --with-system -j2 toolset=msvc address-model=64 link=static threading=multi runtime-link=shared --build-type=minimal --prefix=%luketun_dir%\win -s ZLIB_SOURCE=%zlib_dir% -s ZLIB_INCLUDE=%zlib_dir% -s BZIP2_SOURCE=%bzip2_dir% -s BZIP2_INCLUDE=%bzip2_dir% 

cd %luketun_dir%
pause
