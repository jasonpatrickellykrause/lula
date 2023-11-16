package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"net/http"

	"github.com/defenseunicorns/lula/src/pkg/common/kubernetes"
	"github.com/defenseunicorns/lula/src/types"
	"github.com/mitchellh/mapstructure"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

func ValidateKubernetes(ctx context.Context, data map[string]interface{}) (context.Context, Regoable, []map[string]interface{}, error) {
	// Convert map[string]interface to a RegoTarget
		var payload types.Payload
		err := mapstructure.Decode(data, &payload)
		if err != nil {
			return nil, nil, nil, err
		}

		var resources []unstructured.Unstructured
		resources, err = kube.QueryCluster(ctx, payload)
		if err != nil {
			return nil, nil, nil, err
		}
		// Need []map[string]interface{} for rego validation
		var mapData []map[string]interface{}
		for _, item := range resources {
			mapData = append(mapData, item.Object)
		}

		return ctx, mapData, nil
}

func ValidateAPI(ctx context.Context, data map[string]interface{}) (context.Context, Regoable, []map[string]interface{}, error) {
	var payload types.PayloadAPI
	err := mapstructure.Decode(data, &payload)
	if err != nil {
		return nil, nil, nil, err
	}

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(payload.Request.URL)
	if err != nil {
		return nil, nil, nil, err
	}
	if resp.StatusCode != 200 {
		return nil, nil, nil, fmt.Errorf("expected status code 200 but got %d\n", resp.StatusCode)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, err
	}

	var mapData []map[string]interface{}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "application/json" {

		var prettyBuff bytes.Buffer
		json.Indent(&prettyBuff, body, "", "  ")
		prettyJson := prettyBuff.String()

		// response body must be a list to unmarshal into mapData correctly
		if ! strings.HasPrefix(prettyJson, "[") {
			prettyJson = "["+strings.TrimSpace(prettyJson)+"]"
		}

		err = json.Unmarshal([]byte(prettyJson), &mapData)
		if err != nil {
			return nil, nil, nil, err
		}

	} else {
		return nil, nil, nil, fmt.Errorf("content type %s is not supported", contentType)
	}

	return ctx, payload, mapData, nil
}

func Validate(ctx context.Context, domain string, data map[string]interface{}) (types.Result, error) {
	var payload Regoable
	var mapData []map[string]interface{}
	var err error

	switch domain {
	case "kubernetes":
		ctx, payload, mapData, err = ValidateKubernetes(ctx, data)
		if err != nil {
			return types.Result{}, err
		}

	case "api":
		ctx, payload, mapData, err = ValidateAPI(ctx, data)
		if err != nil {
			return types.Result{}, err
		}

	default:
		return types.Result{}, fmt.Errorf("domain %s is not supported", domain)
	}

	results, err := GetValidatedAssets(ctx, payload.Rego, mapData)
	if err != nil {
		return types.Result{}, err
	}

	return results, nil
}

// GetValidatedAssets performs the validation of the dataset against the given rego policy
func GetValidatedAssets(ctx context.Context, regoPolicy string, dataset []map[string]interface{}) (types.Result, error) {
	var wg sync.WaitGroup
	var matchResult types.Result

	compiler, err := ast.CompileModules(map[string]string{
		"validate.rego": regoPolicy,
	})
	if err != nil {
		log.Fatal(err)
		return matchResult, fmt.Errorf("failed to compile rego policy: %w", err)
	}

	fmt.Printf("Applying policy against %s resources\n", strconv.Itoa(len(dataset)))
	for _, asset := range dataset {
		wg.Add(1)
		go func(asset map[string]interface{}) {
			defer wg.Done()

			regoCalc := rego.New(
				rego.Query("data.validate"),
				rego.Compiler(compiler),
				rego.Input(asset),
			)

			resultSet, err := regoCalc.Eval(ctx)
			if err != nil || resultSet == nil || len(resultSet) == 0 {
				wg.Done()
			}

			for _, result := range resultSet {
				for _, expression := range result.Expressions {
					expressionBytes, err := json.Marshal(expression.Value)
					if err != nil {
						wg.Done()
					}

					var expressionMap map[string]interface{}
					err = json.Unmarshal(expressionBytes, &expressionMap)
					if err != nil {
						wg.Done()
					}
					// TODO: add logging optionality here for developer experience
					if matched, ok := expressionMap["validate"]; ok && matched.(bool) {
						// fmt.Printf("Asset %s matched policy: %s\n\n", asset, expression)
						matchResult.Passing += 1
					} else {
						// fmt.Printf("Asset %s no matched policy: %s\n\n", asset, expression)
						matchResult.Failing += 1
					}
				}
			}
		}(asset)
	}

	wg.Wait()

	return matchResult, nil
}
