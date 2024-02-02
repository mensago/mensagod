package mensagod

/*
* The MIT License
*
* Copyright (c) 2013 Edin Dazdarevic (edin.dazdarevic@gmail.com)

* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:

* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*
*/

// Converted from its original Java to Kotlin

import java.math.BigInteger
import java.net.InetAddress
import java.net.UnknownHostException
import java.nio.ByteBuffer

/**
 * A class that enables to get an IP range from CIDR specification. It supports
 * both IPv4 and IPv6.
 */
class CIDRUtils(private val cidr: String) {
    private var inetAddress: InetAddress? = null
    private var startAddress: InetAddress? = null
    private var endAddress: InetAddress? = null
    private var prefixLength = 0


    init {
        /* split CIDR to address and prefix part */
        if (cidr.contains("/")) {
            val index = cidr.indexOf("/")
            val addressPart = cidr.substring(0, index)
            val networkPart = cidr.substring(index + 1)

            inetAddress = InetAddress.getByName(addressPart)
            prefixLength = networkPart.toInt()

            calculate()
        } else {
            throw IllegalArgumentException("not an valid CIDR format!")
        }
    }


    @Throws(UnknownHostException::class)
    private fun calculate() {
        val maskBuffer: ByteBuffer
        val targetSize: Int
        if (inetAddress!!.address.size == 4) {
            maskBuffer =
                ByteBuffer.allocate(4)
                    .putInt(-1)
            targetSize = 4
        } else {
            maskBuffer = ByteBuffer.allocate(16)
                .putLong(-1L)
                .putLong(-1L)
            targetSize = 16
        }

        val mask = BigInteger(1, maskBuffer.array()).not().shiftRight(prefixLength)

        val buffer = ByteBuffer.wrap(inetAddress!!.address)
        val ipVal = BigInteger(1, buffer.array())

        val startIp = ipVal.and(mask)
        val endIp = startIp.add(mask.not())

        val startIpArr = toBytes(startIp.toByteArray(), targetSize)
        val endIpArr = toBytes(endIp.toByteArray(), targetSize)

        this.startAddress = InetAddress.getByAddress(startIpArr)
        this.endAddress = InetAddress.getByAddress(endIpArr)
    }

    private fun toBytes(array: ByteArray, targetSize: Int): ByteArray {
        var counter = 0
        val newArr = mutableListOf<Byte>()
        while (counter < targetSize && (array.size - 1 - counter >= 0)) {
            newArr.add(0, array[array.size - 1 - counter])
            counter++
        }

        val size = newArr.size
        for (i in 0 until (targetSize - size)) {
            newArr.add(0, 0.toByte())
        }

        val ret = ByteArray(newArr.size)
        for (i in newArr.indices) {
            ret[i] = newArr[i]
        }
        return ret
    }

    val networkAddress: String
        get() = startAddress!!.hostAddress

    val broadcastAddress: String
        get() = endAddress!!.hostAddress

    @Throws(UnknownHostException::class)
    fun isInRange(ipAddress: String?): Boolean {
        val address = InetAddress.getByName(ipAddress)
        val start = BigInteger(
            1,
            startAddress!!.address
        )
        val end = BigInteger(1, endAddress!!.address)
        val target = BigInteger(1, address.address)

        val st = start.compareTo(target)
        val te = target.compareTo(end)

        return (st == -1 || st == 0) && (te == -1 || te == 0)
    }
}
