import fwsimple

fw = fwsimple.Firewall('/home/rick/Source/fwsimple/config/fwsimple.cfg', True)
fw.apply()
