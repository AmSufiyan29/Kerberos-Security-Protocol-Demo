class MD5
{
    private static final int INF_A = 0x67452301;
    private static final int INF_B = (int)0xEFCDAB89L;
    private static final int INF_C = (int)0x98BADCFEL;
    private static final int INF_D = 0x10325476;

    private static final int[] SHIFT_S = {
            7, 12, 17, 22,
            5,  9, 14, 20,
            4, 11, 16, 23,
            6, 10, 15, 21
    };

    private static final int[] TABLE_A = new int[64];
    static
    {
        for (int i = 0; i < 64; i++)
            TABLE_A[i] = (int)(long)((1L << 32) * Math.abs(Math.sin(i + 1)));
    }

    private byte[] compMD5(byte[] message)
    {
        int messageLenBytes = message.length;
        int numBlocks = ((messageLenBytes + 8) >>> 6) + 1;
        int totalLen = numBlocks << 6;
        byte[] paddingBytes = new byte[totalLen - messageLenBytes];
        paddingBytes[0] = (byte)0x80;

        long messageLenBits = (long)messageLenBytes << 3;
        for (int i = 0; i < 8; i++)
        {
            paddingBytes[paddingBytes.length - 8 + i] = (byte)messageLenBits;
            messageLenBits >>>= 8;
        }

        int a = INF_A;
        int b = INF_B;
        int c = INF_C;
        int d = INF_D;
        int[] buffer = new int[16];
        for (int i = 0; i < numBlocks; i ++)
        {
            int index = i << 6;
            for (int j = 0; j < 64; j++, index++)
                buffer[j >>> 2] = ((int)((index < messageLenBytes) ? message[index] : paddingBytes[index - messageLenBytes]) << 24) | (buffer[j >>> 2] >>> 8);
            int orgA = a;
            int orgB = b;
            int orgC = c;
            int orgD = d;
            for (int j = 0; j < 64; j++)
            {
                int div16 = j >>> 4;
                int f = 0;
                int bufferIndex = j;
                switch (div16)
                {
                    case 0:
                        f = (b & c) | (~b & d);
                        break;

                    case 1:
                        f = (b & d) | (c & ~d);
                        bufferIndex = (bufferIndex * 5 + 1) & 0x0F;
                        break;

                    case 2:
                        f = b ^ c ^ d;
                        bufferIndex = (bufferIndex * 3 + 5) & 0x0F;
                        break;

                    case 3:
                        f = c ^ (b | ~d);
                        bufferIndex = (bufferIndex * 7) & 0x0F;
                        break;
                }
                int temp = b + Integer.rotateLeft(a + f + buffer[bufferIndex] + TABLE_A[j], SHIFT_S[(div16 << 2) | (j & 3)]);
                a = d;
                d = c;
                c = b;
                b = temp;
            }

            a += orgA;
            b += orgB;
            c += orgC;
            d += orgD;
        }

        byte[] MD5 = new byte[16];
        int count = 0;
        for (int i = 0; i < 4; i++)
        {
            int n = (i == 0) ? a : ((i == 1) ? b : ((i == 2) ? c : d));
            for (int j = 0; j < 4; j++)
            {
                MD5[count++] = (byte)n;
                n >>>= 8;
            }
        }
        return MD5;
    }

    private String toHexString(byte[] b)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++)
        {
            sb.append(String.format("%02X", b[i] & 0xFF));
        }
        return sb.toString();
    }

    public String hash(String inputStr) {
        return toHexString(compMD5(inputStr.getBytes()));
    }

}