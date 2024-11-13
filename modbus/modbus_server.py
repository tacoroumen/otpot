from pymodbus.server.sync import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

# Modbus data block setup
store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [17]*100),
    co=ModbusSequentialDataBlock(0, [17]*100),
    hr=ModbusSequentialDataBlock(0, [17]*100),
    ir=ModbusSequentialDataBlock(0, [17]*100))
context = ModbusServerContext(slaves=store, single=True)

# Server Identity
identity = ModbusDeviceIdentification()
identity.VendorName = 'Example'
identity.ProductCode = 'PM'
identity.ModelName = 'ModbusServer'
identity.MajorMinorRevision = '1.0'

# Start Modbus server
StartTcpServer(context, identity=identity, address=("0.0.0.0", 502))

