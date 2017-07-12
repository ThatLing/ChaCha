
ChaCha = {}

local error = error
local string_byte = string.byte
local string_char = string.char
local string_len = string.len
local string_format = string.format
local bit_bxor = bit.bxor
local bit_rol = bit.rol
local bit_rshift = bit.rshift
local bit_ror = bit.ror
local bit_band = bit.band
local table_concat = table.concat
local table_remove = table.remove
local table_Copy = table.Copy

function ChaCha.quarterround(t, x, y, z, w)
	t[x] = t[x] + t[y]; t[w] = bit_rol(bit_bxor(t[w], t[x]), 16)
	t[z] = t[z] + t[w]; t[y] = bit_rol(bit_bxor(t[y], t[z]), 12)
	t[x] = t[x] + t[y]; t[w] = bit_rol(bit_bxor(t[w], t[x]), 8)
	t[z] = t[z] + t[w]; t[y] = bit_rol(bit_bxor(t[y], t[z]), 7)
end

function ChaCha.doubleround(x)
	ChaCha.quarterround(x, 1, 	5, 	9, 	13)
	ChaCha.quarterround(x, 2, 	6, 	10, 14)
	ChaCha.quarterround(x, 3, 	7, 	11, 15)
	ChaCha.quarterround(x, 4,	8,	12, 16)
	ChaCha.quarterround(x, 1, 	6,	11,	16)
	ChaCha.quarterround(x, 2, 	7,	12,	13)
	ChaCha.quarterround(x, 3, 	8,	9,	14)
	ChaCha.quarterround(x, 4, 	5,	10,	15)
end

function ChaCha.littleendian(b)
	return 		b[1] 		+ 
		bit_rol(b[2], 8)  	+ 
		bit_rol(b[3], 16) 	+ 
		bit_rol(b[4], 24)
end

function ChaCha.inv_littleendian(b)
	local x0 = bit_band(		b, 			0xFF)
	local x1 = bit_band(bit_ror(b, 8 ), 	0xFF)
	local x2 = bit_band(bit_ror(b, 16), 	0xFF)
	local x3 = bit_band(bit_ror(b, 24), 	0xFF)
	
	return x0, x1, x2, x3
end

function ChaCha.hash(b, rounds)
	local x = {}
	local out = {}
	
	for i = 1, 64, 4 do
		x[#x + 1] = ChaCha.littleendian({b[i], b[i + 1], b[i + 2], b[i + 3]}) 
	end
	
	
	local z = table_Copy(x)
	for i = 1, rounds / 2 do
		ChaCha.doubleround(z)
	end
	
	for i = 1, 16 do
		local p = (i * 4) - 3
		out[p], out[p + 1], out[p + 2], out[p + 3] = ChaCha.inv_littleendian(z[i] + x[i])
	end
	
	return out
end


local t
function ChaCha.expand(k, n, rounds)
	local out = {}
	local keyLen = #k
	local is32Byte = keyLen == 32
	if not t then
		t = { string_byte(string_format("expand %d-byte k", keyLen), 1, -1) }
	end
	
	for i = 1, 16 do
		out[i] 		= t[i]
		out[i + 16] = k[i]
		
		if is32Byte then
			out[i + 32] = k[i + 16]
		else
			out[i + 32] = k[i]
		end
		
		out[i + 48] = n[i]
	end
	
	return ChaCha.hash(out, rounds)
end

function ChaCha.makekey(k, v, counter, rounds)
	local n = {}
	
	for j = 1, 8 do
		n[9 - j] = bit_rshift(bit_band(counter, 0xFF), j * 4)
		n[j + 8] = v[j]
	end
	
	return ChaCha.expand(k, n, rounds), counter + 1
end

function ChaCha.crypt(k, v, m, rounds, counter)
	if #k ~= 32 and #k ~= 16 then
		error("ChaCha.crypt: k must be 16 or 32 bytes in size; got " .. #k)
	end
	
	if #v ~= 8 then
		error("ChaCha.crypt: v must be 8 bytes in size; got " .. #v)
	end
	
	if rounds ~= 20 and rounds ~= 12 and rounds ~= 8 then
		error("ChaCha.crypt: rounds must be 20, 12 or 8; got " .. tostring(rounds))
	end
	
	if not counter then
		counter = 0
	end
	
	local ciphertext = {}
	local key = {}
	t = nil
	
	k = { string_byte(k, 1, -1) }
	v = { string_byte(v, 1, -1) }
	
	for j = 1, string_len(m) do
		if #key == 0 then
			key, counter = ChaCha.makekey(k, v, counter, rounds)
		end
		
		ciphertext[j] = string_char(bit_bxor(string_byte(m, j), key[1]))
		table_remove(key, 1)
	end
	
	return table_concat(ciphertext)
end

