# GNTR
To support cheat development by making it easy to use GDB from Python.

# Example
```python
def main():
	ip = "192.168.2.100"
	pid = 40
	Process = GNTR(ip, pid)
	Process.connect()
	print(Process.read32(0x100000))
	Process.disconnect()
	Process.quit()


if __name__ == "__main__":
	main()
```
