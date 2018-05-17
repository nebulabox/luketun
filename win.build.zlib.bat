set zlib_dir=c:\codes\zlib
set luketun_dir=c:\codes\luketun

call .\win.env.bat

cd %zlib_dir%
mkdir build
cd build
cmake -G"Visual Studio 15 2017 Win64" ..
devenv zlib.sln /build Release /project zlibstatic
mkdir %luketun_dir%\win
mkdir %luketun_dir%\win\include
mkdir %luketun_dir%\win\lib
copy %zlib_dir%\build\Release\zlibstatic.lib %luketun_dir%\win\lib\
copy %zlib_dir%\build\zconf.h %luketun_dir%\win\include\
copy %zlib_dir%\zlib.h %luketun_dir%\win\include\

rd /s /q %zlib_dir%\build\

cd %luketun_dir%
pause

