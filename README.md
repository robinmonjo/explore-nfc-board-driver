### Card polling / writting driver for Explore-NFC board on R-Pi

### Install

* clone this repository onto you R-Pi
* `cd explore-nfc-board-driver`
* Build: `cmake . && make`

### Current support
* Mifare Ultralight

PR are very welcome if anyone need to support other type of cards

### Read data from a card

Run `sudo ./explore-nfc poll`. This will try to read data from a Mifare Ultralight card every second and will output a proper json:

````
{
	"mode" : "poll",
	"uid" : "0410C2620E2981",
	"data" : "68656C6C6F20626974636865730000000000000000000000000000000000000000000000000000000000000000000000"
}
````

### Write data to a card

Run `sudo ./explore-nfc write "data to write"`. This will write "data to write" to each card and will also output a proper json:

````
{
	"mode" : "write",
	"uid" : "0410C2620E2981",
	"data" : "68656C6C6F20626974636865730000000000000000000000000000000000000000000000000000000000000000000000"
}
````

### Full install

For a full install, just `cp` the binary to `/usr/local/bin`

### Resources

* [Mifare Ultralight datasheet](http://www.nxp.com/documents/data_sheet/MF0ICU1.pdf)
* [Code used as a starter](https://github.com/JohnMcLear/NXP-Raspberry-Pi-Card-Polling-Demo), huge thx to John McLear
