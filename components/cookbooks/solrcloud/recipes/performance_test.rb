#
# Cookbook Name :: solrcloud
# Recipe :: performance_test.rb
#
# The recipe will run a performance test on the given compute based on cpu and memory
#
#

execute "performance_test" do
  command "ruby /opt/solr-recipes/vm-performance-stats/performance_test.rb"
end
ruby_block 'parsing the performance_test_log file' do
  block do
    begin
      file = File.open("/opt/solr/log/performance_test_log.txt", "rb")
      contents = file.read
      puts contents
    rescue Exception => e
      puts(e.message)
    end
  end
end