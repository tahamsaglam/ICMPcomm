from bitstring import BitArray

def add_bits(n1, n2):
    result = n1.uint + n2.uint
    if result >= (1 << n1.length):
        result= (result & 0xffff) + (result >> 16)
    return BitArray(uint=result, length=n1.length)


n1="0x4500"
n2="0x001c"
n3="0x3039"
n4="0x0000"
n5="0x8001"
n6="0x0000"
n7="0xc0a8"
n8="0x0127"
n9="0x0808"
n10="0x0808"
nList=[n1,n2,n3,n4,n5,n6,n7,n8,n9,n10]
first=True
for i in range(9):
    print(i)
    if first==True:
        nba = BitArray(nList[i])
        nba2= BitArray(nList[i+1])
        print("first")
        print(nba.bin)
        print(nba2.bin)
        result = add_bits(nba,nba2)
        print("result")
        print(result.bin)
        first=False
    else:
        nba2= BitArray(nList[i+1])
        print(nba2.bin)
        result = add_bits(result,nba2)
        print("result")
        print(result.bin)

    print(result.bin)
# print('''\
#   {:016b}
# + {:016b}
# ------------------
#   {:016b}'''.format(n1,n2,bin(result)))
print(result)
print(~result)
