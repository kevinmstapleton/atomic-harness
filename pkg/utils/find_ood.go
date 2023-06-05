package utils

/*
 * CSV data format and type definitions
 */

/* Find_OutOfDate.Go:
Creates a text file that delineates every criteria which may be out of date based on the commit times to https://github.com/redcanaryco/atomic-red-team/tree/master/atomics
and https://github.com/secureworks/atomic-validation-criteria/tree/master.

Because we cannot assume that there will be the same number of tests as new tests are added, we will need to mark
'not found' tests and either prompt the user to generate the test or do it automatically.

In addition, as an unfortunate consequence of how files are stored in the criteria repo https://github.com/secureworks/atomic-validation-criteria,
we will need to map each test to the file it originated from, since the tests are sometimes stored together (ex. windows/T1027-T1047.csv), and sometimes stored alone (Ex: macos/T1000_macos.csv)
*/

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	types "github.com/secureworks/atomic-harness/pkg/types"
	utils "github.com/secureworks/atomic-harness/pkg/utils"
)

type CommitInfo struct {
	Commit struct {
		Author struct {
			Date string `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

type Content struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func LoadAtomicsFromRepo(repo string, path string) []Content {

	url := "https://api.github.com/repos/" + repo + "/contents/" + path

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Could not read from URL")
		fmt.Print(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Could not parse response body")
		panic(err)
	}

	// fmt.Println(string(body))

	var data []Content

	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println("Improperly Formatted Data: \nGot: " + string(body) + "Expecting: \n{ \n\"name\": string \n\"path\": string \n}")
		panic(err)
	}

	return data

}

func LoadLastCommitDate(repo string, path string) string {

	var date string

	//find the last commit dates to every Technique (to determine which criteria may be out of date)
	url := "https://api.github.com/repos/" + repo + "/commits?path=" + path

	resp, err := http.Get(url)
	if err != nil {
		fmt.Print(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// fmt.Println(string(body))

	var commitResponse []CommitInfo

	err = json.Unmarshal(body, &commitResponse)
	if err != nil {
		panic(err)
	}

	//only need the most recent commit date
	date = commitResponse[0].Commit.Author.Date

	//fmt.Println(string(date))

	jsonData, err := json.Marshal(commitResponse)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("commits.json", jsonData, 0644)
	if err != nil {
		panic(err)
	}

	return date

}

func CompareCommitDates() {

	//Find the path and name of each test currently on redcanary repo
	//redcanaryData := LoadAtomicsFromRepo("redcanaryco/atomic-red-team", "/atomics")
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}

	// We need the data from all platforms, as redcanary does not sort by platform
	// In addition, some of these files will include ranges (ex: T1027-T1047) of tests. We need to determine which file each test is from to compare dates.
	var scwksData []Content = LoadAtomicsFromRepo("secureworks/atomic-validation-criteria", "/windows")
	//scwksData = append(scwksData, LoadAtomicsFromRepo("secureworks/atomic-validation-criteria", "/linux")...)
	scwksData = append(scwksData, LoadAtomicsFromRepo("secureworks/atomic-validation-criteria", "/macos")...)

	fmt.Println("Secureworks Data Files: ", scwksData)

	//dateMap maps the name of the test to the date it was last committed to.
	dateMap := make(map[string]string)

	// regular expression for parsing the TXXX (technique ID) from a string
	re := regexp.MustCompile(`T(\d+)`)

	// first, find the commit date for each file and map the file name to the date it was created.
	for _, file := range scwksData {
		fmt.Println("Test(s): ", file)
		// find first index with this commit date
		date := LoadLastCommitDate("secureworks/atomic-validation-criteria", file.Path)

		fmt.Println("Last date of commit: ", date)

		// if the file contains a '-', assume it is a range of tests. Also assume it is an ascending range.
		if strings.Contains(file.Name, "-") {
			split := strings.Split(file.Name, "-")
			i := split[0]
			j := split[1]
			//use regular expression to get only the technique ID from the rest of the string (excluding any potential .csv, .linux, .macos, etc...)
			match := re.FindStringSubmatch(j)
			if len(match) >= 2 {
				j = match[1]
			}

			// remove the 'T' to be able to cast the strings to integer
			lowerIndex := strings.Trim(i, "T")
			upperIndex := strings.Trim(j, "T")
			lowerBound, err := strconv.Atoi(lowerIndex)

			fmt.Println("Lower Bound:", lowerBound)

			if err != nil {
				fmt.Println(err)
				continue
			}

			upperBound, err := strconv.Atoi(upperIndex)

			if err != nil {
				fmt.Println(err)
			}

			fmt.Println("Upper Bound:", upperBound)

			// Map each Test Index (T1XXX -> T1JJJ) to the date of the commit.
			for lowerBound <= upperBound {
				//assign each possible test index in between these ranges to the parsed date
				var testName = "T" + strconv.Itoa(lowerBound)
				dateMap[testName] = date
				fmt.Println("assigning Test", testName, "(if it exists) to date", date)
				lowerBound++
			}

		} else {
			match := re.FindStringSubmatch(file.Name)
			if len(match) >= 2 {
				mappableFileName := match[1]

				if len(mappableFileName) > 0 {
					fmt.Println("assigning Test", mappableFileName, "(if it exists) to date", date)
					dateMap[mappableFileName] = date
				}

			} else {
				fmt.Print("Expecting a single test containing file, and was unable to parse ", file.Name)
				continue
			}
		}

		//avoid running out of queries
	}

	//just to test if the mapping is working

	fmt.Println(dateMap["T1034"]) // -> this should print the date "2023-05-25T20:38:57Z"

	var found []Content

	var atomicTests = map[string][]*types.TestSpec{} // tid -> tests

	errRead := utils.LoadAtomicsIndexCsv(filepath.FromSlash(cwd+"/../atomic-red-team/atomics"), &atomicTests)

	if errRead != nil {
		fmt.Println("Unable to load Indexes-CSV file for Atomics", errRead)
		os.Exit(1)
	}

	for _, entries := range atomicTests {
		for _, test := range entries {
			cont := Content{test.Technique, "atomics/" + test.Technique}

			//assign each atomic test to the file it originated from in order to parse the last edit date

			//fmt.Println(cont)

			found = append(found, cont)

			// compareDates(test.Technique)

			//avoid duplicates
			break
		}
	}
	/*
		for _, test := range scwksData {
			fmt.Println("Test: ", test)
			found = append(found, test)
		}

			for _, test := range redcanaryData {
				fmt.Println("Test: ", test)
				res := LoadLastCommitDate("redcanaryco/atomic-red-team", test.Path)

				fmt.Println("Last commit date: ", res)
				/*
					res2 := LoadCommitDate("secureworks/atomic-validation-criteria", "/windows")

					if len(res) > 0 {
						fmt.Println(res)
					}

					if len(res2) > 0 {
						fmt.Println(res2)
					}


				//to prevent running out of requests again...
				break
			}
	*/

	fmt.Println("\n\n\n\n")

	/*

		LoadAtomicsFromRepo("secureworks/atomic-validation-criteria", "/linux")

		res := LoadCommitDate("secureworks/atomic-validation-criteria", "/macos")

		fmt.Println(res)

		res2 := LoadCommitDate("redcanaryco/atomic-red-team", "/atomics")

		fmt.Println(res2)
	*/

}
