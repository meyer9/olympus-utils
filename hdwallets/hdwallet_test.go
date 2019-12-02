package hdwallets

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func TestVectors(t *testing.T) {
	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
	testVec2MasterHex := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
	testVec3MasterHex := "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
	hkStart := uint32(0x80000000)

	tests := []struct {
		name     string
		master   string
		path     []uint32
		wantPub  string
		wantPriv string
		net      *Prefixes
	}{
		// Test vector 1
		{
			name:     "test vector 1 chain m",
			master:   testVec1MasterHex,
			path:     []uint32{},
			wantPub:  "xpub1qqqqqqqqqqqqqqp98sty9l9tkryvgcl8q8h6ahfp4lmr8mrxcflsd7pz30yr7vedh6cw7f8x7un2hcwjg3cvt6auqqv9wqugmzzf3dvemc6cz657jsvv8t7tufd4lt0sk8wtu556lrh0amss54mmc",
			wantPriv: "xprv1qqqqqqqqqqqqqqp98sty9l9tkryvgcl8q8h6ahfp4lmr8mrxcflsd7pz30yr7vedhcq987s4yl3sh9zhdt89f3kv6lq3k5v9qend6rw8z8mmvyt99gx6zns598p3r",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 1 chain m/0H",
			master:   testVec1MasterHex,
			path:     []uint32{hkStart},
			wantPub:  "xpub1qx42hmt2sqqqqqpsrua7854vg67dckwkxx3eucdf24u79n9ft5vk0kwv8pftvzkrp7szvz687untmgpurl64grmgdtj46fw4upzz9g0ynyhrl4ckczs8ppt94wr8gwz25yj80t2ujkpmy8qnl9ynp",
			wantPriv: "xprv1qx42hmt2sqqqqqpsrua7854vg67dckwkxx3eucdf24u79n9ft5vk0kwv8pftvzkrpuqq09022s29zx9f6ntfyhajwtt08e4z805klajrqygcj6vx8qv7agcpm8mu8",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 1 chain m/0H/1",
			master:   testVec1MasterHex,
			path:     []uint32{hkStart, 1},
			wantPub:  "xpub1qgf9nkcpqqqqqqd9c35wnjff4f7ec8emay3pea2qgr29m7vryqww32g2cg7m9f5qm6xd2yskntwdw894wqscgd6a5pz605uarktpjhzx49xez4pj4r5xllfp8daw2fjuge7j68eqnhhmczgdsgt2p",
			wantPriv: "xprv1qgf9nkcpqqqqqqd9c35wnjff4f7ec8emay3pea2qgr29m7vryqww32g2cg7m9f5qmcqql7tqf3p373y5qtn7cke6kfjawglwrrh74ky26eeqq9wzxrt9hesfv6x62",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 1 chain m/0H/1/2H",
			master:   testVec1MasterHex,
			path:     []uint32{hkStart, 1, hkStart + 2},
			wantPub:  "xpub1qv0v0y30sqqqqq57nsa2d7zh63ltlhhrrje926h3wanegmsylzh2tu764c0jtsz8d7xsxf40wmmt0kmdn84dcuy59dy08cydt0y4hqrf36qsn29fzx479faz55nm8sgm8hq26q2ar2qjdncha9jlj",
			wantPriv: "xprv1qv0v0y30sqqqqq57nsa2d7zh63ltlhhrrje926h3wanegmsylzh2tu764c0jtsz8duqrtgxf5zefufc8zxj4a7sjed57qjnjlnh53yt7n6pgqzm3haeyk8qkh7weq",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 1 chain m/0H/1/2H/2",
			master:   testVec1MasterHex,
			path:     []uint32{hkStart, 1, hkStart + 2, 2},
			wantPub:  "xpub1q3wkrnr7qqqqqqj2rgpreaxlywh522qrvgrxly4crcj9qkgjmy7m67a0uzp0h8g0yxmq70ppe7vete8ymmudmefpjfv78r50q6gdxrwcz820cxj6ndfneqffc387hqdqmzw5xj26s9m0qas3d96fv",
			wantPriv: "xprv1q3wkrnr7qqqqqqj2rgpreaxlywh522qrvgrxly4crcj9qkgjmy7m67a0uzp0h8g0yyqz3d3tj54rjwprwdlscnknfqnewxhv4wuvcarems9qfvgsl84h97g2v58r5",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 1 chain m/0H/1/2H/2/1000000000",
			master:   testVec1MasterHex,
			path:     []uint32{hkStart, 1, hkStart + 2, 2, 1000000000},
			wantPub:  "xpub1qktq3pjj8wdv5qp76v4r54dz5uuwwalkev7k924nh2suzgn5czqg0d448kpe8ltkzjpj4ve4vpcamlslf6xggj8qx4w9qk86z9yra7tfrjngp3hy723lfghcjrmnm784nc8qf6c5jcdp8yspxrs63",
			wantPriv: "xprv1qktq3pjj8wdv5qp76v4r54dz5uuwwalkev7k924nh2suzgn5czqg0d448kpe8ltkzsq9035d248dtnqt3mj8t83g5xy58h7pqp5cgsc4gku66aq9j43fxlck8ma87",
			net:      BitcoinPrefix,
		},

		// Test vector 2
		{
			name:     "test vector 2 chain m",
			master:   testVec2MasterHex,
			path:     []uint32{},
			wantPub:  "xpub1qqqqqqqqqqqqqqy2dh9kldreyy8jhmvg9qsq7nmy9avv95ha9vd8nnwn045dqdgj4z347aty7usjdvs2uyd8d2ftcfldzsclynjkr9d3f4afdydh5l8aqk8060g4rxwhfuq9t5wadz3rj7g0u825k",
			wantPriv: "xprv1qqqqqqqqqqqqqqy2dh9kldreyy8jhmvg9qsq7nmy9avv95ha9vd8nnwn045dqdgj4qqrgcm32dwa09evyttvct98lnh8n9936539w92cztnfhvttcmchd7srdc8wd",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 2 chain m/0",
			master:   testVec2MasterHex,
			path:     []uint32{0},
			wantPub:  "xpub1q9z3cx75qqqqqqprywtdmev9lj2zhvnxk5m598v27me2nr49a6amcuzxfsgkzevkj7ghzdgk8nt6qua7rd2eplakr5crpy0ety4vxyhyzl3d4g9azld0mpguxew2vfpahwu875zhwc749rq7t6gwx",
			wantPriv: "xprv1q9z3cx75qqqqqqprywtdmev9lj2zhvnxk5m598v27me2nr49a6amcuzxfsgkzevkjuqrlu2wwh39rg3rymcyywnrkvpjxuu08xjtym7r8y949x4mppz7tyc4chsvj",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 2 chain m/0/2147483647H",
			master:   testVec2MasterHex,
			path:     []uint32{0, hkStart + 2147483647},
			wantPub:  "xpub1qfmx8x0yllllll7jrt9ajc6wcvkst2wggakrt3g9mt6xpdznlthz5rp4lr0tew2g0xcteyl6muzln45ug9025pdnvcldg348z0yw5ukgtxpvtn9njq43u5rqhd8fv43rfhcrn49048aqugqmzd0xl",
			wantPriv: "xprv1qfmx8x0yllllll7jrt9ajc6wcvkst2wggakrt3g9mt6xpdznlthz5rp4lr0tew2g0yq8yjmlj7553n9l8w7lxv4r8h9eg0laltreh3vc90qexh4nmnkqdzqhv0kv5",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 2 chain m/0/2147483647H/1",
			master:   testVec2MasterHex,
			path:     []uint32{0, hkStart + 2147483647, 1},
			wantPub:  "xpub1qd96ezygqqqqqqvsv2d8jn0txm8darqfe3u6ee6zrwvr9zqhphdwtsnxddcn7srw32492p0ws95f0q3hshxp6zxsae8ksqx7d89tvc2puu5kqx6rpn0xmdk47qjz4ru8e24fn6ygp2vjcdqegw7lq",
			wantPriv: "xprv1qd96ezygqqqqqqvsv2d8jn0txm8darqfe3u6ee6zrwvr9zqhphdwtsnxddcn7srw3gqzpdv8d6z4sy85py2atphg7fz7tes2x9qgv6dlycjvym0vtqg8tvg68qu2c",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 2 chain m/0/2147483647H/1/2147483646H",
			master:   testVec2MasterHex,
			path:     []uint32{0, hkStart + 2147483647, 1, hkStart + 2147483646},
			wantPub:  "xpub1q3vhl78zllllll4d3d8zh6sgsc94jcpgx294pes5h2enz9kzr3q89mdnqg069k737z62r0qt8y83gz8c3sfk5a9mjdxw0u8qufzmv896am0xpjfa6f5pqartj3s8hjwp07sp3na6erg290c5kudhw",
			wantPriv: "xprv1q3vhl78zllllll4d3d8zh6sgsc94jcpgx294pes5h2enz9kzr3q89mdnqg069k737qqz0ugl9vw7u0jalk2ck733wrff7d7rxn2jr3qnw9md3433ue6sangem66ma",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 2 chain m/0/2147483647H/1/2147483646H/2",
			master:   testVec2MasterHex,
			path:     []uint32{0, hkStart + 2147483647, 1, hkStart + 2147483646, 2},
			wantPub:  "xpub1q5al8ey3qqqqqqsvqendd8en5sjjz65lx3mejntcmjvahakvz6w4eduehxewghwcmjm27yv8005fzfypeeqgh2e9l6wq9pg2zywya8cjgl2zke7spujduh25xypeh40empqsca6unl8a0pq0mn8nh",
			wantPriv: "xprv1q5al8ey3qqqqqqsvqendd8en5sjjz65lx3mejntcmjvahakvz6w4eduehxewghwcmsqzqwdp7xwh3pujs7q0ygxr48lujq752c6s2qmsfpdpu5mmwlz579q5j2axd",
			net:      BitcoinPrefix,
		},

		// Test vector 3
		{
			name:     "test vector 3 chain m",
			master:   testVec3MasterHex,
			path:     []uint32{},
			wantPub:  "xpub1qqqqqqqqqqqqqqr0zl0hr42hcp9k3m0xrw7d7884p85ldqm8ps8dzd59yxp3kmjlszjceqpl727x382jqg4nnex6w4yrz8nnd2wp3k6rtf3940eal0hpnf66wua36xury3x7mwfna2z0cagmlw77y",
			wantPriv: "xprv1qqqqqqqqqqqqqqr0zl0hr42hcp9k3m0xrw7d7884p85ldqm8ps8dzd59yxp3kmjlsqqzr9ap54ecz0m0ceha6dmpa5xur8agqut8hvjen88t8uvhxewnfwg57nf00",
			net:      BitcoinPrefix,
		},
		{
			name:     "test vector 3 chain m/0H",
			master:   testVec3MasterHex,
			path:     []uint32{hkStart},
			wantPub:  "xpub1qylcu0sgsqqqqq94tzqxv5mkzje3xny78lazqnh2mawtg0w4lhcvzjzw8n5055enrwzsmujutm4r64a84xy3vamqf5decle3wj0syd7ttswqwxrf5xlxw25ynxdws5e8c7x7n48suypw6scw6hr3e",
			wantPriv: "xprv1qylcu0sgsqqqqq94tzqxv5mkzje3xny78lazqnh2mawtg0w4lhcvzjzw8n5055enrvqyzreegen8rh7949xwlujqpcthkz7ysgwzal4lltdsxk90nxjjwtcjghee9",
			net:      BitcoinPrefix,
		},
	}
tests:
	for i, test := range tests {
		masterSeed, err := hex.DecodeString(test.master)
		if err != nil {
			t.Errorf("DecodeString #%d (%s): unexpected error: %v",
				i, test.name, err)
			continue
		}

		extKey, err := NewMaster(masterSeed, BitcoinPrefix)
		if err != nil {
			t.Errorf("NewMaster #%d (%s): unexpected error when "+
				"creating new master key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		if extKey.Depth() != uint8(len(test.path)) {
			t.Errorf("Depth of key %d should match fixture path: %v",
				extKey.Depth(), len(test.path))
			continue
		}

		privStr := extKey.String()
		if privStr != test.wantPriv {
			t.Errorf("Serialize #%d (%s): mismatched serialized "+
				"private extended key -- got: %s, want: %s", i,
				test.name, privStr, test.wantPriv)
			continue
		}

		pubKey, err := extKey.Neuter()
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v ", i,
				test.name, err)
			continue
		}

		// Neutering a second time should have no effect.
		pubKey, err = pubKey.Neuter()
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v", i,
				test.name, err)
			return
		}

		pubStr := pubKey.String()
		if pubStr != test.wantPub {
			t.Errorf("Neuter #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

func TestPrivateDerivation(t *testing.T) {
	testVec1MasterPrivKey := "xprv1qqqqqqqqqqqqqqp98sty9l9tkryvgcl8q8h6ahfp4lmr8mrxcflsd7pz30yr7vedhcq987s4yl3sh9zhdt89f3kv6lq3k5v9qend6rw8z8mmvyt99gx6zns598p3r"
	testVec2MasterPrivKey := "xprv1qqqqqqqqqqqqqqy2dh9kldreyy8jhmvg9qsq7nmy9avv95ha9vd8nnwn045dqdgj4qqrgcm32dwa09evyttvct98lnh8n9936539w92cztnfhvttcmchd7srdc8wd"
	tests := []struct {
		name     string
		master   string
		path     []uint32
		wantPriv string
	}{
		// Test vector 1
		{
			name:     "test vector 1 chain m",
			master:   testVec1MasterPrivKey,
			path:     []uint32{},
			wantPriv: "xprv1qqqqqqqqqqqqqqp98sty9l9tkryvgcl8q8h6ahfp4lmr8mrxcflsd7pz30yr7vedhcq987s4yl3sh9zhdt89f3kv6lq3k5v9qend6rw8z8mmvyt99gx6zns598p3r",
		},
		{
			name:     "test vector 1 chain m/0",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0},
			wantPriv: "xprv1qx42hmt2qqqqqq83dpy90llqkudd6apmp39u4j0a4u5vmrk3dhl9g8gguj20qusx7cqqejeel6te739h00dz9gjsgyyzqw5rdjhg3qc9vdnadn3jq5ar99clgythn",
		},
		{
			name:     "test vector 1 chain m/0/1",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1},
			wantPriv: "xprv1qt9punrhqqqqqq0kdqmlanj9je0gpuvh7jg6n7x8ca4c7shmlrfalm2eu6s2mna3vyqrn6qsrnec99l0v96877h5jawtfs03thlea2yxu7hq4sqk0vt8qrcfz732l",
		},
		{
			name:     "test vector 1 chain m/0/1/2",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2},
			wantPriv: "xprv1qdqz80f6qqqqqqn3ery8su6hm7wssvqv24j3v9lwjcj3rmnjyj25wfcdcfugyu6csyqqt0mnc4g60vel5qyt2nfhr527vn5yaynxvcrq76np8h03vvexytqzt546g",
		},
		{
			name:     "test vector 1 chain m/0/1/2/2",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2, 2},
			wantPriv: "xprv1qst6jl49qqqqqq5zxtmd8rj838x42vhr6pu9u5ekp3n6s4e6aq8pgphmee3c2f0fgqqxcpq0vezngvlz2thye8900489tquv2cgxmx98acskjm2cc5cxppgf6mp3w",
		},
		{
			name:     "test vector 1 chain m/0/1/2/2/1000000000",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2, 2, 1000000000},
			wantPriv: "xprv1qkdl6fzd8wdv5qz0ejv8jh0tacn0u5acug84zjruwt8eqq79rpa39sxf4s5aczj33qqz5fqrwhl0tqvh50eynts9fldnu7jfpzs5e4x6m2gu3tmqrrjcnlckgkpty",
		},

		// Test vector 2
		{
			name:     "test vector 2 chain m",
			master:   testVec2MasterPrivKey,
			path:     []uint32{},
			wantPriv: "xprv1qqqqqqqqqqqqqqy2dh9kldreyy8jhmvg9qsq7nmy9avv95ha9vd8nnwn045dqdgj4qqrgcm32dwa09evyttvct98lnh8n9936539w92cztnfhvttcmchd7srdc8wd",
		},
		{
			name:     "test vector 2 chain m/0",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0},
			wantPriv: "xprv1q9z3cx75qqqqqqprywtdmev9lj2zhvnxk5m598v27me2nr49a6amcuzxfsgkzevkjuqrlu2wwh39rg3rymcyywnrkvpjxuu08xjtym7r8y949x4mppz7tyc4chsvj",
		},
		{
			name:     "test vector 2 chain m/0/2147483647",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647},
			wantPriv: "xprv1qfmx8x0y0lllll78gyxsu53ju7clngj933fr0shy35l3rkcmetvlq7cape6kt62t6sqqawqkce2084vd4w6mz6hxvkg6m2mkjg5vsdm4n4mqcfmzfhtyq2s5g0xtj",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1},
			wantPriv: "xprv1qwx4eh2aqqqqqqwgantrd879jhndxanp73r7px7jl2a8xflcmdkqqkudhhsfmde7avqxwjn04ytnzdwd2zv8cmkqn5psxu53tpdzymac98jjsq0t3m7wqvqvkjkcf",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1/2147483646",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1, 2147483646},
			wantPriv: "xprv1qjh35mtw0lllll547vlcx96zgc6qkxu79u3zy5hddqk94ypwf0z93n7d4zyc466xhsqqhl03px93s6fs4ejdqqa9zvz9m4axcj8gxzdw4aw8xze66zhfkqs0m5s2x",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPriv: "xprv1q4g6k6xdqqqqqq47znyvdfh9cwgclu0rdezlak22nfdh4fa4vkwqhmf3dyt8qhxgqsqp7jlyyv3vjeat9calq70p5kcj7c9x7aujeds85wyxleu7jkmzw9sfjvjk9",
		},

		// Custom tests to trigger specific conditions.
		{
			// Seed 000000000000000000000000000000da.
			name:     "Derived privkey with zero high byte m/0",
			master:   "xprv1qqqqqqqqqqqqqqrhrr5cvevaeuw7m89lfhkcnfjwf53034ftwtux7ffxyyupr55vycqxhgevdq8hdmzg4s0yzm90ty4t4uq9d5dllfc65u2ghmcqrzj5q6q7ncsnm",
			path:     []uint32{0},
			wantPriv: "xprv1qyjnhfu3qqqqqqr7aagdn4mllr6l87xqndghduz7d0afs24jc42y86q8ezj908m4wyq92adjtwamwzwfkjtzq694zaerjupajhj8yz9psr8txh92x0ga4zcmjamh2",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewKeyFromString(test.master, nil)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		privStr := extKey.String()
		if privStr != test.wantPriv {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"private extended key -- got: %s, want: %s", i,
				test.name, privStr, test.wantPriv)
			continue
		}
	}
}

func TestPublicDerivation(t *testing.T) {
	testVec1MasterPubKey := "xpub1qqqqqqqqqqqqqqp98sty9l9tkryvgcl8q8h6ahfp4lmr8mrxcflsd7pz30yr7vedh6cw7f8x7un2hcwjg3cvt6auqqv9wqugmzzf3dvemc6cz657jsvv8t7tufd4lt0sk8wtu556lrh0amss54mmc"
	testVec2MasterPubKey := "xpub1qqqqqqqqqqqqqqy2dh9kldreyy8jhmvg9qsq7nmy9avv95ha9vd8nnwn045dqdgj4z347aty7usjdvs2uyd8d2ftcfldzsclynjkr9d3f4afdydh5l8aqk8060g4rxwhfuq9t5wadz3rj7g0u825k"

	tests := []struct {
		name    string
		master  string
		path    []uint32
		wantPub string
	}{
		// Test vector 1
		{
			name:    "test vector 1 chain m",
			master:  testVec1MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub1qqqqqqqqqqqqqqp98sty9l9tkryvgcl8q8h6ahfp4lmr8mrxcflsd7pz30yr7vedh6cw7f8x7un2hcwjg3cvt6auqqv9wqugmzzf3dvemc6cz657jsvv8t7tufd4lt0sk8wtu556lrh0amss54mmc",
		},
		{
			name:    "test vector 1 chain m/0",
			master:  testVec1MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub1qx42hmt2qqqqqq83dpy90llqkudd6apmp39u4j0a4u5vmrk3dhl9g8gguj20qusx76g5uvarhcxt9m0hvpflclczlvrm3vy0zmzjl3hz2attaaz8ekejcynsj4xzpkw0304qur7rxrxc6aq24dxaf",
		},
		{
			name:    "test vector 1 chain m/0/1",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1},
			wantPub: "xpub1qtughsyxqqqqqq2ucelxgfk22twa45e38a88gatzu54dyfxvz6klg7ele7ndzrz57wgf8u09k9jyc702g4z7zwy6kqntwk7wfrax049cfmfl7h37d598hzshgp2ta4fd7g8v4n46dw9q0rcy7hszj",
		},
		{
			name:    "test vector 1 chain m/0/1/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2},
			wantPub: "xpub1qw8nllmjqqqqqq3w063wwmk8j0rvrtnq2ghutj82j6tq5afv8wyxj4kk0el0xdn7exh03wh0gduxq0ngdz8rqvj03rsnnaw7zxzfl0ur5ps00sy0y9y7vkcrmcmfeh4dhcm08f4mnkhfuhgmn62nn",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2},
			wantPub: "xpub1qsyflpcwqqqqqq3zfk79t776z7z09g77lser7l2f948tge2hf9f32rl78ywzdlws6xu6nacqplg7jgfwe9ztjkhh7xfd3gzl4xxwk3cl0s3ugpvw9utyrun2jpd480ps2rn6sxtc394hpxqu9tx68",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2/1000000000",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2, 1000000000},
			wantPub: "xpub1qhzz0f8k8wdv5qzv6n6jgsjvq4awkl7nezm7gmk9dznxl7728ta7m2v3tq2ggq2e92zk8gsezew6eef5wdyn50etv648ncxygvmssj3k8edqwhq8cjcjm29uyyujnmqzq54pvzwtfj5mqpc9kld09",
		},

		// Test vector 2
		{
			name:    "test vector 2 chain m",
			master:  testVec2MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub1qqqqqqqqqqqqqqy2dh9kldreyy8jhmvg9qsq7nmy9avv95ha9vd8nnwn045dqdgj4z347aty7usjdvs2uyd8d2ftcfldzsclynjkr9d3f4afdydh5l8aqk8060g4rxwhfuq9t5wadz3rj7g0u825k",
		},
		{
			name:    "test vector 2 chain m/0",
			master:  testVec2MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub1q9z3cx75qqqqqqprywtdmev9lj2zhvnxk5m598v27me2nr49a6amcuzxfsgkzevkj7z5e8tqmlhdx9pnj3e2xurnh0k35e9scmx9sxf29nm8p0ncvf20jeumn76r3sg9jk25nxms54ga4kc8cwpss",
		},
		{
			name:    "test vector 2 chain m/0/2147483647",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647},
			wantPub: "xpub1qgdur3yz0lllllad8r294dv5shh6c3rgrhyjzyv9cc4a0utt83rstmzacqgajld0j6qvwrvlnz85wdgld2gyvk5qvfemf9cmrzar5plk3wp08x5e0prc363sfcyys7ufmunl6swvuac9w7ck2cxya",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1},
			wantPub: "xpub1qd47k66pqqqqqqv24v6uv7fup9wxma8p5qrcze35zj5ff6u2q3yypwqqzjzynfgnq2rhq68944uvxe70ee5vqggh57crsfnlayakpu2swulhfzshffa57w2z25zgq44t9psfs0wexe9752qkqm3nw",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646},
			wantPub: "xpub1qjh3lamy0llllljqt5vw2nsz6a8da9ctwplydjz7r8qdpy9v924dxxtauk40gjx7njpslamy7mqkazu35cvuhq3wazs0r7wtq0hld2gx7wafexsxf3zl3z5gf52sh6s025xx2v2q4l6pawgugtsfx",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPub: "xpub1q4ra2rj8qqqqqq353vsct5j0sssfjuz850rk9a5l3p9evxh8400nc4f98utt564z3j8pu2d58mxn2x0rcf44690n3ju6el9hhekuxe97v4s7qnjcrnp0ysuckv6ldnhhytt77h44z8j0v8cdcuemn",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewKeyFromString(test.master, nil)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		pubStr := extKey.String()
		if pubStr != test.wantPub {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

func TestExtendedKeyAPI(t *testing.T) {
	tests := []struct {
		name       string
		extKey     string
		isPrivate  bool
		parentFP   uint32
		privKey    string
		privKeyErr error
		pubKey     string
		address    string
	}{
		{
			name:      "test vector 1 master node private",
			extKey:    "xprv1qqqqqqqqqqqqqqp98sty9l9tkryvgcl8q8h6ahfp4lmr8mrxcflsd7pz30yr7vedhcq987s4yl3sh9zhdt89f3kv6lq3k5v9qend6rw8z8mmvyt99gx6zns598p3r",
			isPrivate: true,
			parentFP:  0,
			privKey:   "53fa1527e30b94576ace54c6ccd7c11b51850666dd0dc711f7b611652a0da14e",
			pubKey:    "b0ef24e6f726abe1d24470c5ebbc0018570388d88498b599de35816a9e9418c3afcbe25b5fadf0b1dcbe529af8eefeee",
			address:   "bc1424766nqc45phe0a4ywc2a5kw903qvua7j5nlqsguxfza",
		},
		{
			name:       "test vector 1 chain m/0H/1/2H public",
			extKey:     "xpub1qv0v0y30sqqqqq57nsa2d7zh63ltlhhrrje926h3wanegmsylzh2tu764c0jtsz8d7xsxf40wmmt0kmdn84dcuy59dy08cydt0y4hqrf36qsn29fzx479faz55nm8sgm8hq26q2ar2qjdncha9jlj",
			isPrivate:  false,
			parentFP:   516395567,
			privKeyErr: ErrNotPrivExtKey,
			pubKey:     "8d0326af76f6b7db6d99eadc70942b48f3e08d5bc95b80698e8109a8a911abe2a7a2a527b3c11b3dc0ad015d1a8126cf",
			address:    "bc1t4suclk0pn2t9jgdhp6pfa372tqvvqflgwsva2g4ye59k",
		},
	}

	for i, test := range tests {
		key, err := NewKeyFromString(test.extKey, nil)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected "+
				"error: %v", i, test.name, err)
			continue
		}
		if key.IsPrivate() != test.isPrivate {
			t.Errorf("IsPrivate #%d (%s): mismatched key type -- "+
				"want private %v, got private %v", i, test.name,
				test.isPrivate, key.IsPrivate())
			continue
		}

		parentFP := key.ParentFingerprint()
		if parentFP != test.parentFP {
			t.Errorf("ParentFingerprint #%d (%s): mismatched "+
				"parent fingerprint -- want %d, got %d", i,
				test.name, test.parentFP, parentFP)
			continue
		}

		serializedKey := key.String()
		if serializedKey != test.extKey {
			t.Errorf("String #%d (%s): mismatched serialized key "+
				"-- want %s, got %s", i, test.name, test.extKey,
				serializedKey)
			continue
		}

		privKey, err := key.SecretKey()
		if !reflect.DeepEqual(err, test.privKeyErr) {
			t.Errorf("SecretKey #%d (%s): mismatched error: want "+
				"%v, got %v", i, test.name, test.privKeyErr, err)
			continue
		}
		if test.privKeyErr == nil {
			serialized := privKey.Serialize()
			privKeyStr := hex.EncodeToString(serialized[:])
			if privKeyStr != test.privKey {
				t.Errorf("SecretKey #%d (%s): mismatched "+
					"private key -- want %s, got %s", i,
					test.name, test.privKey, privKeyStr)
				continue
			}
		}

		pubKey, err := key.PubKey()
		if err != nil {
			t.Errorf("PubKey #%d (%s): unexpected error: %v", i,
				test.name, err)
			continue
		}
		serialized := pubKey.Serialize()
		pubKeyStr := hex.EncodeToString(serialized[:])
		if pubKeyStr != test.pubKey {
			t.Errorf("PubKey #%d (%s): mismatched public key -- "+
				"want %s, got %s", i, test.name, test.pubKey,
				pubKeyStr)
			continue
		}

		addr, err := key.Address()
		if err != nil {
			t.Errorf("Address #%d (%s): unexpected error: %v", i,
				test.name, err)
			continue
		}
		if addr != test.address {
			t.Errorf("Address #%d (%s): mismatched address -- want "+
				"%s, got %s", i, test.name, test.address,
				addr)
			continue
		}
	}
}

func TestGenenerateSeed(t *testing.T) {
	wantErr := errors.New("seed length must be between 128 and 512 bits")
	tests := []struct {
		name   string
		length uint8
		err    error
	}{
		// Test various valid lengths.
		{name: "16 bytes", length: 16},
		{name: "17 bytes", length: 17},
		{name: "20 bytes", length: 20},
		{name: "32 bytes", length: 32},
		{name: "64 bytes", length: 64},

		// Test invalid lengths.
		{name: "15 bytes", length: 15, err: wantErr},
		{name: "65 bytes", length: 65, err: wantErr},
	}

	for i, test := range tests {
		seed, err := GenerateSeed(test.length)
		if !reflect.DeepEqual(err, test.err) {
			t.Errorf("GenerateSeed #%d (%s): unexpected error -- "+
				"want %v, got %v", i, test.name, test.err, err)
			continue
		}

		if test.err == nil && len(seed) != int(test.length) {
			t.Errorf("GenerateSeed #%d (%s): length mismatch -- "+
				"got %d, want %d", i, test.name, len(seed),
				test.length)
			continue
		}
	}
}
