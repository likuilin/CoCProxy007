using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;

// By a lot of help from : https://github.com/clanner/cocdp/

namespace CoCProxy007
{
    public struct Packet
    {
        public ushort ID { get; set; }
        public int PayloadLength { get; set; }
        public ushort Unknown { get; set; }
        public byte[] EncryptedMessage { get; set; }

        public static Packet Parse(byte[] buffer, int length)
        {
            byte[] packetId = new byte[2]; // 2 byte - packet id
            byte[] payloadLen = new byte[3]; // 3 byte - payload length

            // maybe one day we know the 'unknown' and use it
            byte[] unknown = new byte[2]; // 2 byte - unknown

            using (MemoryStream memoryStream = new MemoryStream(buffer, 0, length))
            using (BinaryReader binaryReader = new BinaryReader(memoryStream))
            {
                // we do 'Reverse' because it's big endian (like eat egg from down to up)

                // read 2 bytes from first offest
                packetId = binaryReader.ReadBytes(packetId.Length).Reverse().ToArray();

                // read 3 next bytes after packet id bytes
                payloadLen = binaryReader.ReadBytes(payloadLen.Length).Reverse().ToArray();

                // read 2 next bytes after payload length
                unknown = binaryReader.ReadBytes(unknown.Length).Reverse().ToArray();
            }

            // we create new 4 byte array and add payloadLen bytes + one zero byte because theres no int24 in C#
            int payloadLength = BitConverter.ToInt32(new byte[] { payloadLen[0], payloadLen[1], payloadLen[2], 0 }, 0);

            int messageOffest = packetId.Length + payloadLen.Length + unknown.Length; // calculate encrypted message offest

            return new Packet()
                {
                    ID = BitConverter.ToUInt16(packetId, 0), // get packet id from bytes
                    PayloadLength = payloadLength,
                    Unknown = BitConverter.ToUInt16(unknown, 0),
                    // i use 'Take' just for make sure
                    EncryptedMessage = buffer.Skip(messageOffest).Take(payloadLength).ToArray() // get encrypted message
                };
        }
    }
}