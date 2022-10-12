package aws

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

//TODO
//greengrassv2
//synthetics
//amplify
//robomaker
//batch
//opsworks
//codebuild

type EnvsModule struct {
	// General configuration data
	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	AWSProfile   string
	OutputFormat string
	Goroutines   int

	// Service Clients
	ECSClient       *ecs.Client
	LambdaClient    *lambda.Client
	AppRunnerClient *apprunner.Client
	LightsailClient *lightsail.Client
	SagemakerClient *sagemaker.Client

	// Main module data
	EnvironmentVariables []EnvironmentVariable
	CommandCounter       console.CommandCounter
	modLog               *logrus.Entry

	// Used to store output data for pretty printing
	output utils.OutputData2
}

type EnvironmentVariable struct {
	service             string
	name                string
	region              string
	environmentVarName  string
	environmentVarValue string
}

func (m *EnvsModule) PrintEnvs(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "env-vars"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s] Enumerating environment variables in all regions for account %s.\n", cyan(m.output.CallingModule), aws.ToString(m.Caller.Account))
	fmt.Printf("[%s] Supported Services: App Runner, Elastic Container Service, Lambda, Lightsail Containers, Sagemaker \n", cyan(m.output.CallingModule))

	wg := new(sync.WaitGroup)
	semaphore := make(chan struct{}, m.Goroutines)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "tasks")

	//create a channel to receive the objects
	dataReceiver := make(chan EnvironmentVariable)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)
	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, semaphore, dataReceiver)

	}

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	// Send a message to the data receiver goroutine to close the channel and stop
	receiverDone <- true
	<-receiverDone

	sort.Slice(m.EnvironmentVariables, func(i, j int) bool {
		return m.EnvironmentVariables[i].service < m.EnvironmentVariables[j].service
	})

	// Table headers
	m.output.Headers = []string{
		"Service",
		"Region",
		"Name",
		"Key",
		"Value",
	}

	//Table rows
	for _, envVar := range m.EnvironmentVariables {
		m.output.Body = append(
			m.output.Body, []string{
				envVar.service,
				envVar.region,
				envVar.name,
				envVar.environmentVarName,
				envVar.environmentVarValue,
			},
		)
	}
	if len(m.output.Body) > 0 {

		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		fmt.Printf("[%s] %s environment variables found.\n", cyan(m.output.CallingModule), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s] No environment variables found, skipping the creation of an output file.\n", cyan(m.output.CallingModule))
	}
}

func (m *EnvsModule) Receiver(receiver chan EnvironmentVariable, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.EnvironmentVariables = append(m.EnvironmentVariables, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *EnvsModule) executeChecks(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan EnvironmentVariable) {
	defer wg.Done()

	m.CommandCounter.Total++
	wg.Add(1)
	go m.getECSEnvironmentVariablesPerRegion(r, wg, semaphore, dataReceiver)

	m.CommandCounter.Total++
	wg.Add(1)
	go m.getLambdaEnvironmentVariablesPerRegion(r, wg, semaphore, dataReceiver)

	m.CommandCounter.Total++
	wg.Add(1)
	go m.getAppRunnerEnvironmentVariablesPerRegion(r, wg, semaphore, dataReceiver)

	m.CommandCounter.Total++
	wg.Add(1)
	go m.getLightsailEnvironmentVariablesPerRegion(r, wg, semaphore, dataReceiver)

	m.CommandCounter.Total++
	wg.Add(1)
	go m.getSagemakerEnvironmentVariablesPerRegion(r, wg, semaphore, dataReceiver)

}

func (m *EnvsModule) getECSEnvironmentVariablesPerRegion(region string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan EnvironmentVariable) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationMarker *string

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		ListTaskDefinitions, err := m.ECSClient.ListTaskDefinitions(
			context.TODO(),
			&ecs.ListTaskDefinitionsInput{
				NextToken: PaginationMarker,
			},
			func(o *ecs.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, taskDefinitionArn := range ListTaskDefinitions.TaskDefinitionArns {
			DescribeTaskDefinition, err := m.ECSClient.DescribeTaskDefinition(
				context.TODO(),
				&ecs.DescribeTaskDefinitionInput{
					TaskDefinition: &taskDefinitionArn,
				},
			)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			for _, containerDefinition := range DescribeTaskDefinition.TaskDefinition.ContainerDefinitions {
				m.getECSEnvironmentVariablesPerDefinition(containerDefinition, region, dataReceiver)
			}

		}

		// Pagination control. After the last page of output, the for loop exits.
		if ListTaskDefinitions.NextToken != nil {
			PaginationMarker = ListTaskDefinitions.NextToken
		} else {
			PaginationMarker = nil
			break
		}
	}
}

func (m *EnvsModule) getECSEnvironmentVariablesPerDefinition(containerDefinition ecsTypes.ContainerDefinition, region string, dataReceiver chan EnvironmentVariable) {

	if containerDefinition.Environment != nil {
		for _, x := range containerDefinition.Environment {
			dataReceiver <- EnvironmentVariable{
				service:             "ECS",
				name:                aws.ToString(containerDefinition.Name),
				region:              region,
				environmentVarName:  aws.ToString(x.Name),
				environmentVarValue: aws.ToString(x.Value),
			}
		}
	}
}

func (m *EnvsModule) getLambdaEnvironmentVariablesPerRegion(region string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan EnvironmentVariable) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationMarker *string

	// This for loop exits at the end dependeding on whether the output hits its last page (see pagination control block at the end of the loop).
	for {
		functions, err := m.LambdaClient.ListFunctions(
			context.TODO(),
			&lambda.ListFunctionsInput{
				Marker: PaginationMarker,
			},
			func(o *lambda.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, function := range functions.Functions {
			m.getLambdaEnvironmentVariablesPerFunction(function, region, dataReceiver)
		}

		// Pagination control. After the last page of output, the for loop exits.
		if functions.NextMarker != nil {
			PaginationMarker = functions.NextMarker
		} else {
			PaginationMarker = nil
			break
		}
	}
}

func (m *EnvsModule) getLambdaEnvironmentVariablesPerFunction(function lambdaTypes.FunctionConfiguration, region string, dataReceiver chan EnvironmentVariable) {
	if function.Environment != nil {
		for name, value := range function.Environment.Variables {
			dataReceiver <- EnvironmentVariable{
				service:             "Lambda",
				name:                aws.ToString(function.FunctionName),
				region:              region,
				environmentVarName:  name,
				environmentVarValue: value,
			}
		}
	}
}

func (m *EnvsModule) getAppRunnerEnvironmentVariablesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan EnvironmentVariable) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	// "PaginationMarker" is a control variable used for output continuity, as AWS return the output in pages.
	var PaginationControl *string

	for {
		ListServices, err := m.AppRunnerClient.ListServices(
			context.TODO(),
			&(apprunner.ListServicesInput{
				NextToken: PaginationControl,
			}),
			func(o *apprunner.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}
		if len(ListServices.ServiceSummaryList) > 0 {

			for _, service := range ListServices.ServiceSummaryList {
				name := aws.ToString(service.ServiceName)
				arn := aws.ToString(service.ServiceArn)
				awsService := "App Runner"

				DescribeService, err := m.AppRunnerClient.DescribeService(
					context.TODO(),
					&apprunner.DescribeServiceInput{
						ServiceArn: &arn,
					},
					func(o *apprunner.Options) {
						o.Region = r
					},
				)
				if err != nil {
					m.modLog.Error(err.Error())
					m.CommandCounter.Error++
					break

				}

				if len(DescribeService.Service.SourceConfiguration.ImageRepository.ImageConfiguration.RuntimeEnvironmentVariables) > 0 {
					for k, v := range DescribeService.Service.SourceConfiguration.ImageRepository.ImageConfiguration.RuntimeEnvironmentVariables {
						//fmt.Printf("%s - %s", k, v)
						dataReceiver <- EnvironmentVariable{
							service:             awsService,
							name:                name,
							region:              r,
							environmentVarName:  k,
							environmentVarValue: v,
						}
					}
				}

			}
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListServices.NextToken != nil {
			PaginationControl = ListServices.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
}

func (m *EnvsModule) getLightsailEnvironmentVariablesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan EnvironmentVariable) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	awsService := "Lightsail [Container]"

	GetContainerServices, err := m.LightsailClient.GetContainerServices(
		context.TODO(),
		&(lightsail.GetContainerServicesInput{}),
		func(o *lightsail.Options) {
			o.Region = r
		},
	)

	if err != nil {
		m.modLog.Error(err.Error())
		m.CommandCounter.Error++
		return
	}

	if err == nil {

		if len(GetContainerServices.ContainerServices) > 0 {

			for _, containerService := range GetContainerServices.ContainerServices {
				for _, container := range containerService.CurrentDeployment.Containers {
					for k, v := range container.Environment {
						name := aws.ToString(containerService.ContainerServiceName)
						dataReceiver <- EnvironmentVariable{
							service:             awsService,
							name:                name,
							region:              r,
							environmentVarName:  k,
							environmentVarValue: v,
						}
					}
				}

			}
		}
	}
}

func (m *EnvsModule) getSagemakerEnvironmentVariablesPerRegion(r string, wg *sync.WaitGroup, semaphore chan struct{}, dataReceiver chan EnvironmentVariable) {
	defer func() {
		m.CommandCounter.Executing--
		m.CommandCounter.Complete++
		wg.Done()

	}()
	semaphore <- struct{}{}
	defer func() {
		<-semaphore
	}()
	// m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	awsService := "Sagemaker"

	var PaginationControl *string

	// Look for envs in processing jobs
	for {
		ListProcessingJobs, err := m.SagemakerClient.ListProcessingJobs(
			context.TODO(),
			&(sagemaker.ListProcessingJobsInput{
				NextToken: PaginationControl,
			}),
			func(o *sagemaker.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, job := range ListProcessingJobs.ProcessingJobSummaries {
			jobName := job.ProcessingJobName

			DescribeProcessingJob, err := m.SagemakerClient.DescribeProcessingJob(
				context.TODO(),
				&(sagemaker.DescribeProcessingJobInput{
					ProcessingJobName: jobName,
				}),
				func(o *sagemaker.Options) {
					o.Region = r
				},
			)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}

			if len(DescribeProcessingJob.Environment) > 0 {
				name := fmt.Sprintf("[Processing Job] %s", aws.ToString(DescribeProcessingJob.ProcessingJobName))
				for k, v := range DescribeProcessingJob.Environment {
					dataReceiver <- EnvironmentVariable{
						service:             awsService,
						name:                name,
						region:              r,
						environmentVarName:  k,
						environmentVarValue: v,
					}
				}

			}
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListProcessingJobs.NextToken != nil {
			PaginationControl = ListProcessingJobs.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	// Look for envs in transcoding jobs

	var PaginationControl2 *string

	for {
		ListTransformJobs, err := m.SagemakerClient.ListTransformJobs(
			context.TODO(),
			&(sagemaker.ListTransformJobsInput{
				NextToken: PaginationControl2,
			}),
			func(o *sagemaker.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, job := range ListTransformJobs.TransformJobSummaries {
			jobName := job.TransformJobName

			DescribeTransformJob, err := m.SagemakerClient.DescribeTransformJob(
				context.TODO(),
				&(sagemaker.DescribeTransformJobInput{
					TransformJobName: jobName,
				}),
				func(o *sagemaker.Options) {
					o.Region = r
				},
			)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			if err == nil {

				if len(DescribeTransformJob.Environment) > 0 {
					name := fmt.Sprintf("[Transform Job] %s", aws.ToString(DescribeTransformJob.TransformJobName))
					for k, v := range DescribeTransformJob.Environment {
						dataReceiver <- EnvironmentVariable{
							service:             awsService,
							name:                name,
							region:              r,
							environmentVarName:  k,
							environmentVarValue: v,
						}
					}
				}
			}
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListTransformJobs.NextToken != nil {
			PaginationControl2 = ListTransformJobs.NextToken
		} else {
			PaginationControl2 = nil
			break
		}
	}

	// Look for envs in transcoding jobs

	var PaginationControl3 *string

	for {
		ListTrainingJobs, err := m.SagemakerClient.ListTrainingJobs(
			context.TODO(),
			&(sagemaker.ListTrainingJobsInput{
				NextToken: PaginationControl3,
			}),
			func(o *sagemaker.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, job := range ListTrainingJobs.TrainingJobSummaries {
			jobName := job.TrainingJobName

			DescribeTrainingJob, err := m.SagemakerClient.DescribeTrainingJob(
				context.TODO(),
				&(sagemaker.DescribeTrainingJobInput{
					TrainingJobName: jobName,
				}),
				func(o *sagemaker.Options) {
					o.Region = r
				},
			)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			if err == nil {

				if len(DescribeTrainingJob.Environment) > 0 {
					name := fmt.Sprintf("[Training Job] %s", aws.ToString(DescribeTrainingJob.TrainingJobName))
					for k, v := range DescribeTrainingJob.Environment {
						dataReceiver <- EnvironmentVariable{
							service:             awsService,
							name:                name,
							region:              r,
							environmentVarName:  k,
							environmentVarValue: v,
						}

					}
				}
			}
		}

		// The "NextToken" value is nil when there's no more data to return.
		if ListTrainingJobs.NextToken != nil {
			PaginationControl3 = ListTrainingJobs.NextToken
		} else {
			PaginationControl3 = nil
			break
		}
	}

	// Look for envs in transcoding jobs

	var PaginationControl4 *string

	for {
		ListModels, err := m.SagemakerClient.ListModels(
			context.TODO(),
			&(sagemaker.ListModelsInput{
				NextToken: PaginationControl4,
			}),
			func(o *sagemaker.Options) {
				o.Region = r
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, model := range ListModels.Models {
			modelName := model.ModelName
			DescribeModel, err := m.SagemakerClient.DescribeModel(
				context.TODO(),
				&(sagemaker.DescribeModelInput{
					ModelName: modelName,
				}),
				func(o *sagemaker.Options) {
					o.Region = r
				},
			)
			if err != nil {
				m.modLog.Error(err.Error())
				m.CommandCounter.Error++
				break
			}
			if err == nil {

				if len(DescribeModel.PrimaryContainer.Environment) > 0 {
					name := fmt.Sprintf("[Model] %s", aws.ToString(DescribeModel.ModelName))
					for k, v := range DescribeModel.PrimaryContainer.Environment {
						dataReceiver <- EnvironmentVariable{
							service:             awsService,
							name:                name,
							region:              r,
							environmentVarName:  k,
							environmentVarValue: v,
						}
					}
				}
			}
		}
		// The "NextToken" value is nil when there's no more data to return.
		if ListModels.NextToken != nil {
			PaginationControl4 = ListModels.NextToken
		} else {
			PaginationControl4 = nil
			break
		}

	}
}
