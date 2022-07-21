# include("index.jl")

using SBP
using Test

@testset "Test SBP core selectors" begin
  sbp("sbp/selectors/unsafe", ["test/unsafe"])

  @testset "it should register selectors" begin
    sels = sbp("sbp/selectors/register", Dict(
      "test/safe1" => () -> nothing,
      "test/safe2" => (testData :: Any) -> testData,
      "test/unsafe" => () -> nothing,
    ))
    @test length(sels) === 3
    @test isa(sbp("sbp/selectors/fn", "test/safe1"), Function)
  end

  @testset "It should call function" begin
    testData = 1
    @test sbp("test/safe2", testData) === testData
  end

  @testset "It should fail to overwrite" begin
    @test_throws ErrorException sbp("sbp/selectors/overwrite", Dict(
      "test/safe1" => () -> println("foo")
    ))
  end

  @testset "It should overwrite" begin
    sbp("sbp/selectors/overwrite", Dict(
      "test/unsafe" => () -> "foo"
    ))
    @test sbp("test/unsafe") === "foo"
  end

  # TODO: test filters
end
