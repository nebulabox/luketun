rem Recommend open folder in vs2017 directly

call .\win.env.bat
mkdir build
cd build
cmake -G "Visual Studio 15 2017 Win64" ..
cd ..

pause
