package helpers

import "fmt"

func ExampleIsDomainName() {
	t := Target{
		Value: "example.com",
	}
	isDN, err := t.IsDomainName()
	if err != nil {
		fmt.Print(err)
	}
	fmt.Print(isDN)

	isHN, err := t.IsHostname()
	if err != nil {
		fmt.Print(err)
	}
	fmt.Print(isHN)

	isIP := t.IsIP()
	fmt.Print(isIP)

	// Output:truetruefalse

}
