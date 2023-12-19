package dnsmsg

import "testing"

func TestNameString(t *testing.T) {
	cases := []struct {
		n   NName
		str string
	}{
		{n: NName{}, str: ""},
		{n: NName{Length: 1}, str: "."},
		{n: NName{Name: [255]byte{1, 'a', 0}, Length: 3}, str: "a."},
		{n: NName{Name: [255]byte{2, 'a', 'A', 0}, Length: 3}, str: "aA."},
		{n: NName{Name: [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}, str: "example.com."},
		{n: NName{Name: [255]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}, str: "www.example.com."},
		{n: NName{Name: [255]byte{3, 'W', 'w', 'W', 7, 'e', 'X', 'a', 'm', 'p', 'L', 'e', 3, 'c', 'O', 'm', 0}, Length: 13}, str: "WwW.eXampLe.cOm."},
		{n: NName{Name: [255]byte{2, '~', '!', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}, str: "~!.example.com."},
		{n: NName{Name: [255]byte{4, 0x20, 0x7F, '.', '\\', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}, str: "\\032\\127\\.\\\\.example.com."},
	}

	for _, tt := range cases {
		if str := tt.n.String(); str != tt.str {
			t.Errorf("(%v).String() = %q; want = %q", tt.n.Name[:tt.n.Length], str, tt.str)
		}
	}
}

func TestNameEqual(t *testing.T) {
	cases := []struct {
		n1, n2 NName
		eq     bool
	}{
		{n1: NName{}, n2: NName{}, eq: true},
		{n1: NName{Length: 1}, n2: NName{Length: 1}, eq: true},
		{n1: NName{Length: 1}, n2: NName{}, eq: false},
		{
			n1: NName{Name: [255]byte{1, 'a', 0}, Length: 3},
			n2: NName{Name: [255]byte{1, 'a', 0}, Length: 3},
			eq: true,
		},
		{
			n1: NName{Name: [255]byte{1, 'a', 0}, Length: 3},
			n2: NName{Name: [255]byte{1, 'A', 0}, Length: 3},
			eq: true,
		},
		{
			n1: NName{Name: [255]byte{1, 'a', 0}, Length: 3},
			n2: NName{Name: [255]byte{1, 'b', 0}, Length: 3},
			eq: false,
		},
		{
			n1: NName{Name: [255]byte{1, 'a', 0}, Length: 3},
			n2: NName{Name: [255]byte{2, 'a', 'a', 0}, Length: 4},
			eq: false,
		},

		{
			n1: NName{
				Name:   [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
				Length: 13,
			},
			n2: NName{
				Name:   [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
				Length: 13,
			},
			eq: true,
		},
		{
			n1: NName{
				Name:   [255]byte{7, 'E', 'x', 'A', 'm', 'p', 'L', 'e', 3, 'c', 'O', 'm', 0},
				Length: 13,
			},
			n2: NName{
				Name:   [255]byte{7, 'E', 'X', 'a', 'm', 'p', 'l', 'E', 3, 'C', 'o', 'm', 0},
				Length: 13,
			},
			eq: true,
		},
		{
			n1: NName{
				Name:   [255]byte{3, 'w', 'w', 'w', 7, 'E', 'x', 'A', 'm', 'p', 'L', 'e', 3, 'c', 'O', 'm', 0},
				Length: 17,
			},
			n2: NName{
				Name:   [255]byte{7, 'E', 'X', 'a', 'm', 'p', 'l', 'E', 3, 'C', 'o', 'm', 0},
				Length: 13,
			},
			eq: false,
		},
		{
			n1: NName{
				Name:   [255]byte{3, 'w', 'w', 'w', 7, 'E', 'x', 'A', 'm', 'p', 'L', 'e', 3, 'c', 'O', 'm', 0},
				Length: 17,
			},
			n2: NName{
				Name:   [255]byte{4, 'i', 'm', 'a', 'p', 7, 'E', 'X', 'a', 'm', 'p', 'l', 'E', 3, 'C', 'o', 'm', 0},
				Length: 18,
			},
			eq: false,
		},
		{
			n1: NName{
				Name:   [255]byte{1, 'a', 2, 'w', 'w', 3, 'w', 'w', 'w', 0},
				Length: 10,
			},
			n2: NName{
				Name:   [255]byte{1, 'a', 3, 'w', 'w', 'w', 2, 'w', 'w', 0},
				Length: 10,
			},
			eq: false,
		},
	}

	for _, tt := range cases {
		if eq := tt.n1.Equal(&tt.n2); eq != tt.eq {
			t.Errorf("(%v).Equal(%v) = %v; want = %v",
				tt.n1.Name[:tt.n2.Length],
				tt.n2.Name[:tt.n2.Length],
				eq, tt.eq,
			)
		}
		if eq := tt.n2.Equal(&tt.n1); eq != tt.eq {
			t.Errorf("(%v).Equal(%v) = %v; want = %v",
				tt.n2.Name[:tt.n2.Length],
				tt.n1.Name[:tt.n1.Length],
				eq, tt.eq,
			)
		}
	}
}
