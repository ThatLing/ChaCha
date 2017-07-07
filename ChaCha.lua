
ChaCha = {}

local string_byte = string.byte
local string_char = string.char
local string_len = string.len
local string_format = string.format
local bit_bxor = bit.bxor
local bit_rol = bit.rol
local bit_ror = bit.ror
local bit_rshift = bit.rshift
local bit_band = bit.band
local table_concat = table.concat
local table_Copy = table.Copy

function ChaCha.quarterround(y0, y1, y2, y3)
	y0 = y0 + y1; y3 = bit_rol(bit_bxor(y3, y0), 16)
	y2 = y2 + y3; y1 = bit_rol(bit_bxor(y1, y2), 12)
	y0 = y0 + y1; y3 = bit_rol(bit_bxor(y3, y0), 8)
	y2 = y2 + y3; y1 = bit_rol(bit_bxor(y1, y2), 7)
		
	return y0, y1, y2, y3
end

function ChaCha.doubleround(x)
	local y = x
	
	y[1], 	y[5], 	y[9], 	y[13] = ChaCha.quarterround(y[1], 	y[5], 	y[9], 	y[13])
	y[2], 	y[6], 	y[10], 	y[14] = ChaCha.quarterround(y[2], 	y[6], 	y[10], 	y[14])
	y[3], 	y[7], 	y[11], 	y[15] = ChaCha.quarterround(y[3], 	y[7], 	y[11], 	y[15])
	y[4], 	y[8],	y[12], 	y[16] = ChaCha.quarterround(y[4],	y[8],	y[12], 	y[16])
	y[1],	y[6],	y[11],	y[16] = ChaCha.quarterround(y[1], 	y[6],	y[11],	y[16])
	y[2],	y[7],	y[12],	y[13] = ChaCha.quarterround(y[2], 	y[7],	y[12],	y[13])
	y[3],	y[8],	y[9],	y[14] = ChaCha.quarterround(y[3], 	y[8],	y[9],	y[14])
	y[4],	y[5],	y[10],	y[15] = ChaCha.quarterround(y[4], 	y[5],	y[10],	y[15])
	
	return y
end

function ChaCha.littleendian(b)
	return b[1] + b[2] * (2 ^ 8) + b[3] * (2 ^ 16) + b[4] * (2 ^ 24)
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
	
	for i = 1, 16 do
		local p = (i * 4) - 3
		x[i] = ChaCha.littleendian({b[p], b[p + 1], b[p + 2], b[p + 3]}) 
	end
	
	
	local z = table_Copy(x)
	for i = 1, rounds / 2 do
		z = ChaCha.doubleround(z)
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

function ChaCha.makekey(k, v, i, rounds)
	local n = {}
	
	for j = 1, 8 do
		n[9 - j] = bit_rshift(bit_band(i, 0xFF), j * 4)
		n[j + 8] = v[j]
	end
	
	return ChaCha.expand(k, n, rounds), i + 1
end

function ChaCha.crypt(k, v, m, rounds)
	if #k ~= 32 and #k ~= 16 then
		error("ChaCha.crypt: k must be 16 or 32 bytes in size; got " .. #k)
	end
	
	if #v ~= 8 then
		error("ChaCha.crypt: v must be 8 bytes in size; got " .. #v)
	end
	
	if rounds ~= 20 and rounds ~= 12 and rounds ~= 8 then
		error("ChaCha.crypt: rounds must be 20, 12 or 8; got " .. tostring(rounds))
	end
	
	
	local ciphertext = {}
	local i = 0
	local key = {}
	t = nil
	
	k = { string_byte(k, 1, -1) }
	v = { string_byte(v, 1, -1) }
	
	for j = 1, string_len(m) do
		if j % 64 == 1 then
			key, i = ChaCha.makekey(k, v, i, rounds)
		end
		
		ciphertext[j] = string_char(bit_bxor(string_byte(m, j), key[((j - 1) % 64) + 1]))
	end
	
	return table_concat(ciphertext)
end
