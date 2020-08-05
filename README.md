<center><h1> Python3 PortScanner</h1></center>

<center><i><h3>Here I am presenting you one of the fastest open source port scanners out there.</br>
This portscanner pings the target host in order to get the average ping and then </br>
proceeds to use that + a few milliseconds, as the maximum timeout for each socket.</br>
For it to better and faster handle the scanning, it creates threads and assings </br>
each thread a range of 257 ports to scan. After the scan is done it tells you the time</br>
it took since thee command was executed until the scan is done, and also saves the </br>
data in a JSON file. I recommend using PyPy as I have been able to get better results</br>
with it. Down below I have posted some benchmarks of using PyPy and not using it.</br>
Results may vary depending on each servers firewall and ping.</h3></i></br></center>


## Requirements
- pythonping module
- python 3.6+

</br></br>



#### Disclaimer: <i><h5>I am not responsible for any illegal usage of this program.<i><h5>
